//! Tests for [`miden_standards::account::oracle::PriceFeed`], the published-price implementation
//! behind a [`miden_standards::account::oracle::PriceOracle`].

use miden_protocol::Felt;
use miden_protocol::account::StorageMapKey;
use miden_standards::account::oracle::{FeedPriceKey, PriceEntry, PriceFeed, PriceOracleError};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_PRICE_FEED_PRICE_ZERO;
use miden_testing::{MockChain, assert_transaction_executor_error};

use super::common::{consumer_account, oracle_account, source_faucet, usd};

/// Prices supplied at genesis land in the map the rate computation reads, keyed by the canonical
/// faucet id word.
#[test]
fn the_component_seeds_the_quote_and_the_published_prices() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_500u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let account = oracle_account(&[(source_faucet()?, entry)])?;
    let storage = account.storage();

    assert_eq!(storage.get_item(PriceFeed::quote_slot())?, usd()?.as_word());
    assert_eq!(
        storage.get_map_item(
            PriceFeed::prices_slot(),
            StorageMapKey::new(FeedPriceKey::from_faucet_id(source_faucet()?).as_word())
        )?,
        entry.to_word()
    );

    Ok(())
}

/// A zero price is how the feed encodes "not published", so it cannot also be a published value.
#[test]
fn a_zero_price_cannot_be_constructed() {
    assert_eq!(
        PriceEntry::new(Felt::ZERO, 2, MockChain::TIMESTAMP_START_SECS),
        Err(PriceOracleError::PriceZero)
    );
}

/// An exponent beyond the supported range is refused at construction, matching the assertion the
/// feed makes on chain.
#[test]
fn an_out_of_range_exponent_cannot_be_constructed() {
    let exponent = PriceEntry::MAX_EXPONENT + 1;

    assert_eq!(
        PriceEntry::new(Felt::from(1u32), exponent, MockChain::TIMESTAMP_START_SECS),
        Err(PriceOracleError::ExponentOutOfRange(exponent))
    );
}

/// `publish_price` writes the entry the rate computation later reads.
#[tokio::test]
async fn publish_price_writes_the_entry() -> anyhow::Result<()> {
    let account = oracle_account(&[])?;

    let faucet_id_word = FeedPriceKey::from_faucet_id(source_faucet()?).as_word();
    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_feed

        @transaction_script
        pub proc main
            push.{timestamp} push.{exponent} push.{price} push.{faucet_id_word}
            # => [FAUCET_ID, price, exponent, timestamp, ...]

            call.price_feed::publish_price

            exec.sys::truncate_stack
        end
        "#,
        timestamp = MockChain::TIMESTAMP_START_SECS,
        exponent = 6u32,
        price = 42u32,
    ))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mut mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        mock_chain
            .committed_account(account.id())?
            .storage()
            .get_map_item(PriceFeed::prices_slot(), StorageMapKey::new(faucet_id_word))?,
        PriceEntry::new(Felt::from(42u32), 6, MockChain::TIMESTAMP_START_SECS)?.to_word()
    );

    Ok(())
}

/// The on-chain guard mirrors the Rust one: a zero price is rejected at publication, which is what
/// lets a zero price read back as "not published" without ambiguity.
#[tokio::test]
async fn publishing_a_zero_price_is_rejected() -> anyhow::Result<()> {
    let account = oracle_account(&[])?;
    let _ = consumer_account([33; 32])?;

    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_feed

        @transaction_script
        pub proc main
            push.{timestamp} push.0 push.0 push.{faucet_id_word}
            # => [FAUCET_ID, price = 0, exponent = 0, timestamp, ...]

            call.price_feed::publish_price

            exec.sys::truncate_stack
        end
        "#,
        timestamp = MockChain::TIMESTAMP_START_SECS,
        faucet_id_word = FeedPriceKey::from_faucet_id(source_faucet()?).as_word(),
    ))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PRICE_FEED_PRICE_ZERO);

    Ok(())
}
