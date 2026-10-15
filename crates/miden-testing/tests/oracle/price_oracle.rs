//! Tests for [`miden_standards::account::oracle::PriceOracle`], the price oracle interface.
//!
//! Every test reaches `get_conversion_rate` the way a consumer does: over FPI, by the wrapper's
//! MAST root. The pricing behind it is supplied by test-only rate providers, because the point
//! under test is the interface and its dispatch, not any particular way of deriving a rate.

use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;
use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    AccountType,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::transaction::ExecutedTransaction;
use miden_standards::account::access::Authority;
use miden_standards::account::oracle::PriceOracle;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_PRICE_ORACLE_LAST_UPDATED_DEN_MISMATCH,
    ERR_PRICE_ORACLE_LAST_UPDATED_NOT_U32,
    ERR_PRICE_ORACLE_RATE_PROVIDER_NOT_IN_ACCOUNT,
    ERR_PRICE_ORACLE_RATE_PROVIDER_ROOT_IS_ZERO,
};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use rstest::rstest;

// TEST RATE PROVIDERS
// ================================================================================================

const RATE_PROVIDERS_PATH: &str = "test::oracle::rate_providers";

/// Rate providers with the shape `get_conversion_rate` dispatches to. They report fixed rates and
/// update timestamps so a test can tell which one answered.
const RATE_PROVIDERS_CODE: &str = r#"
    use miden::core::sys

    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc fixed_rate_1500_over_3
        dropw dropw
        # => [pad(8)]

        push.3 push.1500 push.1000
        # => [last_updated, num, den, pad(8)]

        exec.sys::truncate_stack
    end

    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc fixed_rate_7_over_1
        dropw dropw
        # => [pad(8)]

        push.1 push.7 push.2000
        # => [last_updated, num, den, pad(8)]

        exec.sys::truncate_stack
    end

    #! A rate provider that prices nothing, standing in for one whose data is missing or too old
    #! to rely on. Both cases report the same rate.
    #!
    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc unpriced
        dropw dropw
        # => [pad(8)]

        push.0 push.0 push.0
        # => [last_updated = 0, num = 0, den = 0, pad(8)]

        exec.sys::truncate_stack
    end

    #! A rate provider breaking the contract with a last_updated of 2^32, one past the u32 range.
    #!
    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc last_updated_above_u32
        dropw dropw
        # => [pad(8)]

        push.1 push.1 push.4294967296
        # => [last_updated, num, den, pad(8)]

        exec.sys::truncate_stack
    end

    #! A rate provider breaking the contract by marking the pair unpriced while still handing out
    #! a rate, which a caller skipping the check would convert at.
    #!
    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc unpriced_with_rate
        dropw dropw
        # => [pad(8)]

        push.3 push.1500 push.0
        # => [last_updated = 0, num, den, pad(8)]

        exec.sys::truncate_stack
    end

    #! A rate provider breaking the contract by marking the pair priced with a zero rate.
    #!
    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc priced_without_rate
        dropw dropw
        # => [pad(8)]

        push.0 push.0 push.1000
        # => [last_updated, num = 0, den = 0, pad(8)]

        exec.sys::truncate_stack
    end
"#;

/// A rate provider that is compiled but never installed on the oracle account, so its root is a
/// well-formed procedure root the account does not carry.
const FOREIGN_PROVIDER_PATH: &str = "test::oracle::foreign_provider";

const FOREIGN_PROVIDER_CODE: &str = r#"
    use miden::core::sys

    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [last_updated, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc fixed_rate_2_over_1
        dropw dropw
        # => [pad(8)]

        push.1 push.2 push.3000
        # => [last_updated, num, den, pad(8)]

        exec.sys::truncate_stack
    end
"#;

// HELPERS
// ================================================================================================

/// Compiles the test rate providers component.
fn rate_providers_code() -> anyhow::Result<AccountComponentCode> {
    Ok(CodeBuilder::default().compile_component_code(RATE_PROVIDERS_PATH, RATE_PROVIDERS_CODE)?)
}

/// Returns the procedure root of one of the test rate providers.
fn rate_provider_root(
    code: &AccountComponentCode,
    name: &str,
) -> anyhow::Result<AccountProcedureRoot> {
    code.get_procedure_root_by_path(format!("{RATE_PROVIDERS_PATH}::{name}").as_str())
        .ok_or_else(|| anyhow::anyhow!("component should export {name}"))
}

/// Builds an oracle account carrying the test rate providers, with `active` registered as the one
/// the interface dispatches to.
fn oracle_account(
    code: &AccountComponentCode,
    active: AccountProcedureRoot,
) -> anyhow::Result<Account> {
    let oracle = PriceOracle::new(active);

    let providers = AccountComponent::new(
        code.clone(),
        Vec::new(),
        AccountComponentMetadata::mock(RATE_PROVIDERS_PATH),
    )?;

    Ok(AccountBuilder::new([31; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(oracle)
        .with_component(providers)
        .build_existing()?)
}

/// Builds a consumer account that reaches the oracle through a transaction script.
fn consumer_account() -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([32; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?)
}

/// Returns the asset id word of a fungible asset issued by the given faucet.
fn asset_id_of(faucet_id: u128) -> anyhow::Result<Word> {
    Ok(FungibleAsset::new(AccountId::try_from(faucet_id)?, 1)?.id().into())
}

/// Builds a transaction script reading a rate over FPI and asserting what came back.
fn assert_rate_tx_script_code(
    oracle_id: AccountId,
    expected_last_updated: u64,
    expected_num: u64,
    expected_den: u64,
) -> anyhow::Result<String> {
    Ok(format!(
        r#"
        use miden::core::sys
        use miden::protocol::tx

        @transaction_script
        pub proc main
            # `get_conversion_rate` takes two words, so the rest of the frame is padding
            padw padw
            push.{target_asset_id} push.{source_asset_id}
            # => [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]

            push.{rate_root}
            push.{oracle_prefix} push.{oracle_suffix}
            # => [oracle_id_suffix, oracle_id_prefix, GET_CONVERSION_RATE_ROOT,
            #     foreign_procedure_inputs(16)]

            exec.tx::execute_foreign_procedure
            # => [last_updated, num, den, pad(13)]

            push.{expected_last_updated} assert_eq.err="unexpected last_updated timestamp"
            push.{expected_num} assert_eq.err="unexpected rate numerator"
            push.{expected_den} assert_eq.err="unexpected rate denominator"
            # => [pad(13)]

            exec.sys::truncate_stack
        end
        "#,
        source_asset_id = asset_id_of(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?,
        target_asset_id = asset_id_of(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?,
        rate_root = *PriceOracle::get_conversion_rate_root().mast_root(),
        oracle_prefix = oracle_id.prefix().as_felt(),
        oracle_suffix = oracle_id.suffix(),
    ))
}

/// Reads a rate over FPI from an oracle dispatching to the named test provider, asserting the
/// given values came back, and returns the outcome.
async fn read_rate(
    provider: &str,
    expected_last_updated: u64,
    expected_num: u64,
    expected_den: u64,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let code = rate_providers_code()?;
    let oracle = oracle_account(&code, rate_provider_root(&code, provider)?)?;
    let consumer = consumer_account()?;

    let tx_script = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        expected_last_updated,
        expected_num,
        expected_den,
    )?)?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(consumer.clone())?;
    let mock_chain = builder.build()?;

    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;

    Ok(mock_chain
        .build_transaction(consumer.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await)
}

// TESTS
// ================================================================================================

/// The interface hands back whatever the registered rate provider produced, unchanged.
#[tokio::test]
async fn the_interface_returns_the_rate_providers_rate() -> anyhow::Result<()> {
    read_rate("fixed_rate_1500_over_3", 1_000, 1_500, 3).await??;

    Ok(())
}

/// Replacing the rate provider leaves the interface's procedure root untouched, so a consumer that
/// resolved it before the swap keeps reaching the oracle afterwards and sees the new pricing.
#[tokio::test]
async fn swapping_the_rate_provider_keeps_the_interface_reachable() -> anyhow::Result<()> {
    let code = rate_providers_code()?;
    let oracle = oracle_account(&code, rate_provider_root(&code, "fixed_rate_1500_over_3")?)?;
    let consumer = consumer_account()?;
    let next_root = rate_provider_root(&code, "fixed_rate_7_over_1")?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(consumer.clone())?;
    let mut mock_chain = builder.build()?;

    // the originally registered provider answers
    let before = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        1_000,
        1_500,
        3,
    )?)?;
    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;
    mock_chain
        .build_transaction(consumer.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(before)
        .build()?
        .execute()
        .await?;

    // swap the rate provider
    let swap = CodeBuilder::default()
        .compile_tx_script(set_rate_provider_tx_script_code(*next_root.mast_root()))?;
    let executed = mock_chain
        .build_transaction(oracle.id())
        .tx_script(swap)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        mock_chain
            .committed_account(oracle.id())?
            .storage()
            .get_item(PriceOracle::active_rate_provider_slot())?,
        *next_root.mast_root(),
        "set_rate_provider should have registered the new provider"
    );

    // the same wrapper root now answers with the new provider's pricing
    let after = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        2_000,
        7,
        1,
    )?)?;
    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;
    mock_chain
        .build_transaction(consumer.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(after)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// A pair the rate provider cannot price comes back as all zeros, unchanged, rather than aborting
/// inside the oracle. The consumer decides what an unpriceable pair means to it, and one that does
/// not check still fails closed once the zero rate reaches `fee::convert_amount`.
#[tokio::test]
async fn an_unpriceable_pair_comes_back_as_all_zeros() -> anyhow::Result<()> {
    read_rate("unpriced", 0, 0, 0).await??;

    Ok(())
}

/// Callers apply u32 arithmetic to `last_updated`, so the interface refuses a provider value past
/// the u32 range rather than handing it on. The script expects exactly what the provider returns,
/// so only the interface's own check can make it fail.
#[tokio::test]
async fn a_last_updated_past_the_u32_range_is_rejected() -> anyhow::Result<()> {
    let result = read_rate("last_updated_above_u32", 1 << 32, 1, 1).await?;

    // `u32assert` raises a `U32AssertionFailed` (not a plain `FailedAssertion`), so match the
    // variant explicitly and assert on its error code.
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { err_code, .. },
            ..
        } if err_code == ERR_PRICE_ORACLE_LAST_UPDATED_NOT_U32.code()
    );

    Ok(())
}

/// A zero `last_updated` is what marks a pair unpriced, so the interface refuses a provider whose
/// `last_updated` and denominator disagree.
#[rstest]
#[case::unpriced_with_rate("unpriced_with_rate", 0, 1_500, 3)]
#[case::priced_without_rate("priced_without_rate", 1_000, 0, 0)]
#[tokio::test]
async fn a_last_updated_disagreeing_with_the_rate_is_rejected(
    #[case] provider: &str,
    #[case] last_updated: u64,
    #[case] num: u64,
    #[case] den: u64,
) -> anyhow::Result<()> {
    let result = read_rate(provider, last_updated, num, den).await?;

    assert_transaction_executor_error!(result, ERR_PRICE_ORACLE_LAST_UPDATED_DEN_MISMATCH);

    Ok(())
}

/// Builds a transaction script pointing the oracle at `root`.
fn set_rate_provider_tx_script_code(root: Word) -> String {
    format!(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_oracle

        @transaction_script
        pub proc main
            push.{root}
            # => [RATE_PROVIDER_PROC_ROOT, ...]

            call.price_oracle::set_rate_provider

            exec.sys::truncate_stack
        end
        "#
    )
}

/// Runs a `set_rate_provider` transaction against a freshly built oracle and returns the outcome.
async fn set_rate_provider(
    root: Word,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let code = rate_providers_code()?;
    let oracle = oracle_account(&code, rate_provider_root(&code, "fixed_rate_1500_over_3")?)?;

    let tx_script =
        CodeBuilder::default().compile_tx_script(set_rate_provider_tx_script_code(root))?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    let mock_chain = builder.build()?;

    Ok(mock_chain
        .build_transaction(oracle.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await)
}

/// A root the account does not carry can never be reached by `dyncall`, so it is refused at write
/// time rather than bricking every later read.
#[tokio::test]
async fn setting_a_rate_provider_outside_the_account_is_rejected() -> anyhow::Result<()> {
    let foreign = CodeBuilder::default()
        .compile_component_code(FOREIGN_PROVIDER_PATH, FOREIGN_PROVIDER_CODE)?;
    let foreign_root = foreign
        .get_procedure_root_by_path(
            format!("{FOREIGN_PROVIDER_PATH}::fixed_rate_2_over_1").as_str(),
        )
        .ok_or_else(|| anyhow::anyhow!("component should export fixed_rate_2_over_1"))?;

    let result = set_rate_provider(*foreign_root.mast_root()).await?;

    assert_transaction_executor_error!(result, ERR_PRICE_ORACLE_RATE_PROVIDER_NOT_IN_ACCOUNT);

    Ok(())
}

/// The empty root is refused too, since it would leave the oracle unable to answer at all.
#[tokio::test]
async fn setting_a_zero_rate_provider_is_rejected() -> anyhow::Result<()> {
    let result = set_rate_provider(Word::empty()).await?;

    assert_transaction_executor_error!(result, ERR_PRICE_ORACLE_RATE_PROVIDER_ROOT_IS_ZERO);

    Ok(())
}
