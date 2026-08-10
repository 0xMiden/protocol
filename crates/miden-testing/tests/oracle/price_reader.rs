//! Tests for [`miden_standards::account::oracle::PriceReaderManager`], the consuming side of the
//! price oracle standard.
//!
//! Its conversion procedures are `exec`-invoked by design, so the tests install a thin test
//! component exposing them at a `call` boundary, the way a real consumer component would.

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::oracle::{PriceEntry, PriceReaderManager};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_PRICE_READER_MANAGER_ORACLE_NOT_CONFIGURED,
    ERR_PRICE_READER_RATE_STALE,
};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use super::common::{asset_id_of, oracle_account, source_faucet, target_faucet, unpriced_faucet};

const CONVERT_COMPONENT_PATH: &str = "test::oracle::convert";

/// Exposes the reader's `exec`-invoked conversions at a `call` boundary so a transaction script can
/// observe them.
const CONVERT_COMPONENT_CODE: &str = r#"
    use miden::core::sys
    use miden::standards::oracle::price_reader
    use miden::standards::oracle::price_reader_manager

    #! Inputs:  [ASSET_ID, ASSET_VALUE, TARGET_ASSET_ID, pad(4)]
    #! Outputs: [converted_amount, timestamp, pad(14)]
    #!
    #! Invocation: call
    @account_procedure
    pub proc convert_asset_amount
        exec.price_reader_manager::convert_asset_amount

        exec.sys::truncate_stack
    end

    #! Inputs:  [ASSET_ID, ASSET_VALUE, TARGET_ASSET_ID, max_age_secs, pad(3)]
    #! Outputs: [converted_amount, pad(15)]
    #!
    #! Invocation: call
    @locals(1)
    @account_procedure
    pub proc convert_asset_amount_fresh
        movup.12 loc_store.0
        # => [ASSET_ID, ASSET_VALUE, TARGET_ASSET_ID, pad(3)]

        exec.price_reader_manager::convert_asset_amount
        # => [converted_amount, timestamp, pad(3)]

        swap loc_load.0 exec.price_reader::assert_fresh
        # => [converted_amount, pad(3)]

        exec.sys::truncate_stack
    end
"#;

/// Compiles the test conversion component.
fn convert_component_code() -> anyhow::Result<AccountComponentCode> {
    Ok(CodeBuilder::default()
        .compile_component_code(CONVERT_COMPONENT_PATH, CONVERT_COMPONENT_CODE)?)
}

/// Builds a reader account pointed at `oracle`, alongside the test conversion component.
fn reader_account(oracle: Option<&Account>, code: AccountComponentCode) -> anyhow::Result<Account> {
    let manager = match oracle {
        Some(oracle) => PriceReaderManager::new().with_oracle(oracle.id()),
        None => PriceReaderManager::new(),
    };

    let convert_component = AccountComponent::new(
        code,
        Vec::new(),
        AccountComponentMetadata::mock(CONVERT_COMPONENT_PATH),
    )?;

    Ok(AccountBuilder::new([34; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(manager)
        .with_component(convert_component)
        .build_existing()?)
}

/// Builds a transaction script converting an amount and asserting the result.
fn convert_tx_script_code(
    source: AccountId,
    amount: u64,
    target: AccountId,
    expected_amount: u64,
) -> anyhow::Result<String> {
    Ok(format!(
        r#"
        use miden::core::sys
        use test::oracle::convert

        @transaction_script
        pub proc main
            padw
            push.{target_asset_id}
            push.0.0.0.{amount} push.{source_asset_id}
            # => [ASSET_ID, ASSET_VALUE, TARGET_ASSET_ID, pad(4)]

            call.convert::convert_asset_amount
            # => [converted_amount, timestamp, pad(14)]

            push.{expected_amount} assert_eq.err="unexpected converted amount"
            drop
            # => [pad(14)]

            exec.sys::truncate_stack
        end
        "#,
        source_asset_id = asset_id_of(source)?,
        target_asset_id = asset_id_of(target)?,
    ))
}

/// The reader multiplies the amount by the rate, so a converted amount reflects both the price
/// ratio and how much is being moved.
#[tokio::test]
async fn converting_applies_the_rate_to_the_amount() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;
    let oracle = oracle_account(&[
        (source_faucet()?, PriceEntry::new(Felt::from(1_500u32), 2, now)?),
        (target_faucet()?, PriceEntry::new(Felt::from(3u32), 0, now)?),
    ])?;
    let code = convert_component_code()?;
    let reader = reader_account(Some(&oracle), code.clone())?;

    // the rate is 1_500 / 300 = 5, so 4 source units are worth 20 target units
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(code.as_package())?
        .compile_tx_script(convert_tx_script_code(source_faucet()?, 4, target_faucet()?, 20)?)?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(reader.clone())?;
    let mock_chain = builder.build()?;

    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;

    mock_chain
        .build_transaction(reader.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// An asset the oracle cannot price yields a zero denominator, which `fee::convert_amount` refuses,
/// so a caller that does not branch on it fails closed instead of valuing the asset at nothing.
#[tokio::test]
async fn converting_an_unpriceable_asset_aborts() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;
    let oracle = oracle_account(&[(target_faucet()?, PriceEntry::new(Felt::from(3u32), 0, now)?)])?;
    let code = convert_component_code()?;
    let reader = reader_account(Some(&oracle), code.clone())?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(code.as_package())?
        .compile_tx_script(convert_tx_script_code(unpriced_faucet()?, 4, target_faucet()?, 0)?)?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(reader.clone())?;
    let mock_chain = builder.build()?;

    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;

    let result = mock_chain
        .build_transaction(reader.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert!(result.is_err(), "converting an unpriceable asset should abort");

    Ok(())
}

/// A reader with no oracle attached refuses to convert rather than reading account id zero.
#[tokio::test]
async fn converting_without_a_configured_oracle_aborts() -> anyhow::Result<()> {
    let code = convert_component_code()?;
    let reader = reader_account(None, code.clone())?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(code.as_package())?
        .compile_tx_script(convert_tx_script_code(source_faucet()?, 4, target_faucet()?, 0)?)?;

    let mut builder = MockChain::builder();
    builder.add_account(reader.clone())?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(reader.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PRICE_READER_MANAGER_ORACLE_NOT_CONFIGURED);

    Ok(())
}

/// Freshness is the consumer's call, applied to the timestamp the rate carries: a rate older than
/// the bound the consumer picked is refused.
#[tokio::test]
async fn a_rate_older_than_the_consumers_bound_is_refused() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;
    let stale = now - 7_200;
    let oracle = oracle_account(&[
        (source_faucet()?, PriceEntry::new(Felt::from(1_500u32), 2, stale)?),
        (target_faucet()?, PriceEntry::new(Felt::from(3u32), 0, now)?),
    ])?;
    let code = convert_component_code()?;
    let reader = reader_account(Some(&oracle), code.clone())?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(code.as_package())?
        .compile_tx_script(format!(
            r#"
        use miden::core::sys
        use test::oracle::convert

        @transaction_script
        pub proc main
            push.0.0.0.60
            push.{target_asset_id}
            push.0.0.0.4 push.{source_asset_id}
            # => [ASSET_ID, ASSET_VALUE, TARGET_ASSET_ID, max_age_secs, pad(3)]

            call.convert::convert_asset_amount_fresh

            exec.sys::truncate_stack
        end
        "#,
            source_asset_id = asset_id_of(source_faucet()?)?,
            target_asset_id = asset_id_of(target_faucet()?)?,
        ))?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(reader.clone())?;
    let mock_chain = builder.build()?;

    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;

    let result = mock_chain
        .build_transaction(reader.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PRICE_READER_RATE_STALE);

    Ok(())
}

/// The reader stores the oracle it was configured with.
#[test]
fn the_component_seeds_the_oracle_account() -> anyhow::Result<()> {
    let oracle = oracle_account(&[])?;
    let reader = reader_account(Some(&oracle), convert_component_code()?)?;

    assert_eq!(
        reader.storage().get_item(PriceReaderManager::oracle_slot())?,
        Word::new([oracle.id().prefix().as_felt(), oracle.id().suffix(), Felt::ZERO, Felt::ZERO])
    );

    Ok(())
}
