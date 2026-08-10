//! Tests for [`miden_standards::account::oracle::PriceFeed`], the publishing side of the price
//! oracle standard.
//!
//! `get_price` is the procedure every consumer invokes over FPI, so its exact stack layout is part
//! of the standard rather than an implementation detail. `get_price_returns_the_canonical_stack`
//! pins that layout: it calls the procedure directly and asserts every returned felt, so a change
//! to the contract fails here rather than silently in a consumer.

use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::oracle::{FeedPriceKey, PriceEntry, PriceFeed, QuoteId};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

// HELPERS
// ================================================================================================

/// Returns the faucet whose price the tests publish.
fn priced_faucet() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?)
}

/// Returns a faucet no test publishes a price for.
fn unpriced_faucet() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?)
}

/// Returns the quote unit the test feeds publish in.
fn usd() -> anyhow::Result<QuoteId> {
    Ok(QuoteId::from_symbol("USD")?)
}

/// Builds a price feed account publishing `entries`, gated by its own auth component.
fn price_feed_account(
    entries: impl IntoIterator<Item = (AccountId, PriceEntry)>,
) -> anyhow::Result<Account> {
    let mut feed = PriceFeed::new(usd()?);
    for (faucet_id, entry) in entries {
        feed = feed.with_price(faucet_id, entry);
    }

    Ok(AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(feed)
        .build_existing()?)
}

/// Builds a transaction script that calls `get_price` for `faucet_id` and asserts every returned
/// felt against the expected values.
fn assert_get_price_tx_script_code(
    faucet_id: AccountId,
    expected_is_tracked: u64,
    expected_price: u64,
    expected_exponent: u64,
    expected_timestamp: u64,
) -> String {
    let faucet_id_word = FeedPriceKey::from_faucet_id(faucet_id).as_word();

    format!(
        r#"
        use miden::standards::oracle::price_feed

        @transaction_script
        pub proc main
            padw padw padw push.{faucet_id_word}
            # => [FAUCET_ID, pad(12)]

            call.price_feed::get_price
            # => [is_tracked, price, exponent, timestamp, pad(12)]

            push.{expected_is_tracked} assert_eq.err="unexpected is_tracked"
            push.{expected_price} assert_eq.err="unexpected price"
            push.{expected_exponent} assert_eq.err="unexpected exponent"
            push.{expected_timestamp} assert_eq.err="unexpected timestamp"
            # => [pad(12)]

            dropw dropw dropw
        end
        "#
    )
}

// TESTS
// ================================================================================================

/// The component seeds the quote slot and the prices map from its Rust-side configuration, keyed by
/// the canonical `[prefix, suffix, 0, 0]` faucet id word the MASM builds.
#[test]
fn component_seeds_quote_and_prices() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, 1_700_000_000)?;
    let account = price_feed_account([(priced_faucet()?, entry)])?;

    assert_eq!(account.storage().get_item(PriceFeed::quote_slot())?, usd()?.as_word());

    let stored = account.storage().get_map_item(
        PriceFeed::prices_slot(),
        StorageMapKey::new(FeedPriceKey::from_faucet_id(priced_faucet()?).as_word()),
    )?;
    assert_eq!(stored, entry.to_word());

    // an unpublished faucet reads back as the empty word, which is what makes `is_tracked` fall out
    // of a zero price rather than needing a separate flag
    let missing = account.storage().get_map_item(
        PriceFeed::prices_slot(),
        StorageMapKey::new(FeedPriceKey::from_faucet_id(unpriced_faucet()?).as_word()),
    )?;
    assert_eq!(missing, Word::empty());

    Ok(())
}

/// `get_price` returns exactly `[is_tracked, price, exponent, timestamp]`. This is the contract
/// every consumer of the standard compiles against, so it is asserted felt by felt.
#[tokio::test]
async fn get_price_returns_the_canonical_stack() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let account = price_feed_account([(priced_faucet()?, entry)])?;

    let tx_script = CodeBuilder::default().compile_tx_script(assert_get_price_tx_script_code(
        priced_faucet()?,
        1,
        1_200,
        2,
        u64::from(MockChain::TIMESTAMP_START_SECS),
    ))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// A faucet with no published price reads back as untracked, with the remaining fields zeroed.
#[tokio::test]
async fn get_price_reports_an_unpublished_faucet_as_untracked() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let account = price_feed_account([(priced_faucet()?, entry)])?;

    let tx_script = CodeBuilder::default().compile_tx_script(assert_get_price_tx_script_code(
        unpriced_faucet()?,
        0,
        0,
        0,
        0,
    ))?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// A zero price is reserved to mean "not tracked", so it cannot be published.
#[test]
fn a_zero_price_cannot_be_published() {
    assert!(PriceEntry::new(Felt::ZERO, 2, 1_700_000_000).is_err());
}

/// `publish_price` writes the entry the reader later reads, keyed by the canonical faucet id word.
#[tokio::test]
async fn publish_price_writes_the_entry() -> anyhow::Result<()> {
    let account = price_feed_account([])?;

    let faucet_id_word = FeedPriceKey::from_faucet_id(priced_faucet()?).as_word();
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

    let stored = mock_chain.committed_account(account.id())?.storage().get_map_item(
        PriceFeed::prices_slot(),
        StorageMapKey::new(FeedPriceKey::from_faucet_id(priced_faucet()?).as_word()),
    )?;
    assert_eq!(
        stored,
        PriceEntry::new(Felt::from(42u32), 6, MockChain::TIMESTAMP_START_SECS)?.to_word()
    );

    Ok(())
}
