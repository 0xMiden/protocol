//! Tests for [`miden_standards::account::oracle::PriceOracle`], the price oracle interface.
//!
//! Every test reaches `get_conversion_rate` the way a consumer does: over FPI, by the wrapper's
//! MAST root. The pricing behind it is supplied by test-only rate providers, because the point
//! under test is the interface and its dispatch, not any particular way of deriving a rate.

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
use miden_standards::account::access::Authority;
use miden_standards::account::oracle::PriceOracle;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

// TEST RATE PROVIDERS
// ================================================================================================

const RATE_PROVIDERS_PATH: &str = "test::oracle::rate_providers";

/// Rate providers with the shape `get_conversion_rate` dispatches to. They report fixed rates so a
/// test can tell which one answered.
const RATE_PROVIDERS_CODE: &str = r#"
    use miden::core::sys

    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [has_conversion_rate, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc fixed_rate_1500_over_3
        dropw dropw
        # => [pad(8)]

        push.3 push.1500 push.1
        # => [has_conversion_rate, num, den, pad(8)]

        exec.sys::truncate_stack
    end

    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [has_conversion_rate, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc fixed_rate_7_over_1
        dropw dropw
        # => [pad(8)]

        push.1 push.7 push.1
        # => [has_conversion_rate, num, den, pad(8)]

        exec.sys::truncate_stack
    end

    #! A rate provider that prices nothing, standing in for one whose data is missing or too old
    #! to rely on. Both cases report the same rate.
    #!
    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [has_conversion_rate, num, den, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc unpriced
        dropw dropw
        # => [pad(8)]

        push.0 push.0 push.0
        # => [has_conversion_rate = 0, num = 0, den = 0, pad(8)]

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
    expected_has_rate: u64,
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
            # => [has_conversion_rate, num, den, pad(13)]

            push.{expected_has_rate} assert_eq.err="unexpected has_conversion_rate flag"
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

// TESTS
// ================================================================================================

/// The interface hands back whatever the registered rate provider produced, unchanged.
#[tokio::test]
async fn the_interface_returns_the_rate_providers_rate() -> anyhow::Result<()> {
    let code = rate_providers_code()?;
    let oracle = oracle_account(&code, rate_provider_root(&code, "fixed_rate_1500_over_3")?)?;
    let consumer = consumer_account()?;

    let tx_script = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        1,
        1_500,
        3,
    )?)?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(consumer.clone())?;
    let mock_chain = builder.build()?;

    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;

    mock_chain
        .build_transaction(consumer.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

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
        1,
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
    let swap = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_oracle

        @transaction_script
        pub proc main
            push.{next_root}
            # => [RATE_PROVIDER_PROC_ROOT, ...]

            call.price_oracle::set_rate_provider

            exec.sys::truncate_stack
        end
        "#,
        next_root = *next_root.mast_root(),
    ))?;
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
        1,
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

/// A pair the rate provider cannot price comes back as a zero denominator, unchanged, rather than
/// aborting inside the oracle. The consumer decides what an unpriceable pair means to it, and one
/// that does not check still fails closed once the rate reaches `fee::convert_amount`.
#[tokio::test]
async fn an_unpriceable_pair_comes_back_as_a_zero_denominator() -> anyhow::Result<()> {
    let code = rate_providers_code()?;
    let oracle = oracle_account(&code, rate_provider_root(&code, "unpriced")?)?;
    let consumer = consumer_account()?;

    let tx_script = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        0,
        0,
        0,
    )?)?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(consumer.clone())?;
    let mock_chain = builder.build()?;

    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;

    mock_chain
        .build_transaction(consumer.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}
