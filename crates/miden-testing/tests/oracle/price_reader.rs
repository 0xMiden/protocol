//! Tests for [`miden_standards::account::oracle::PriceReaderManager`], the consuming side of the
//! price oracle standard.
//!
//! The reader reaches the feed over FPI, so every test here composes two accounts: a feed that
//! publishes unit prices and a reader that values an asset against it. The reader's
//! `quote_asset_value` is `exec`-invoked by design, so the tests install a thin test component that
//! exposes it at a `call` boundary.
//!
//! No mock feed is hand-written in MASM: the tests deploy the real [`PriceFeed`] component and seed
//! its storage, so what is exercised is the shipped code rather than a stand-in that can drift from
//! it.

use std::collections::BTreeMap;

use miden_protocol::account::component::AccountComponentCode;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::oracle::{
    FeedPriceKey,
    PriceEntry,
    PriceFeed,
    PriceReaderConfig,
    PriceReaderManager,
    QuoteId,
    UntrackedAssetPolicy,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_PRICE_READER_PRICE_STALE,
    ERR_PRICE_READER_QUOTE_MISMATCH,
    ERR_PRICE_READER_UNTRACKED_ASSET_REJECTED,
};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;

// HELPERS
// ================================================================================================

/// A test-only component exposing the reader's `exec`-invoked valuation at a `call` boundary, so a
/// transaction script can observe its result.
const QUOTE_ASSET_COMPONENT_PATH: &str = "test::oracle::quote_asset";

const QUOTE_ASSET_COMPONENT_CODE: &str = r#"
    use miden::core::sys
    use miden::standards::oracle::price_reader_manager

    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [is_tracked, value_in_quote, pad(14)]
    #!
    #! Invocation: call
    @account_procedure
    pub proc quote_asset_value
        exec.price_reader_manager::quote_asset_value

        # the reader stashes the asset in locals, which drops the operand stack to its 16-felt
        # floor, so the call frame's depth is restored explicitly
        exec.sys::truncate_stack
    end
"#;

/// Returns the faucet whose asset the tests value.
fn priced_faucet() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?)
}

/// Returns a faucet the feed publishes no price for.
fn unpriced_faucet() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?)
}

/// Returns the quote unit the test feed publishes in.
fn usd() -> anyhow::Result<QuoteId> {
    Ok(QuoteId::from_symbol("USD")?)
}

/// Compiles the test valuation component.
fn quote_asset_component_code() -> anyhow::Result<AccountComponentCode> {
    Ok(CodeBuilder::default()
        .compile_component_code(QUOTE_ASSET_COMPONENT_PATH, QUOTE_ASSET_COMPONENT_CODE)?)
}

/// Builds a price feed account publishing a single price for [`priced_faucet`].
fn feed_account(entry: PriceEntry) -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(PriceFeed::new(usd()?).with_price(priced_faucet()?, entry))
        .build_existing()?)
}

/// Builds a reader account pointed at `feed`, alongside the test valuation component.
fn reader_account(
    feed: &Account,
    quote_exponent: u32,
    max_age_secs: u32,
    untracked_policy: UntrackedAssetPolicy,
    component_code: AccountComponentCode,
) -> anyhow::Result<Account> {
    reader_account_with_price_keys(
        feed,
        quote_exponent,
        max_age_secs,
        untracked_policy,
        component_code,
        BTreeMap::new(),
    )
}

/// Builds a reader account as [`reader_account`] does, with feed price key overrides.
fn reader_account_with_price_keys(
    feed: &Account,
    quote_exponent: u32,
    max_age_secs: u32,
    untracked_policy: UntrackedAssetPolicy,
    component_code: AccountComponentCode,
    feed_price_keys: BTreeMap<AccountId, FeedPriceKey>,
) -> anyhow::Result<Account> {
    let config = PriceReaderConfig::builder()
        .feed_account_id(feed.id())
        .get_price_proc_root(PriceFeed::get_price_root())
        .quote_id(usd()?)
        .quote_exponent(quote_exponent)
        .max_age_secs(max_age_secs)
        .untracked_policy(untracked_policy)
        .feed_price_keys(feed_price_keys)
        .build();

    let quote_asset_component = miden_protocol::account::AccountComponent::new(
        component_code,
        alloc::vec::Vec::new(),
        miden_protocol::account::component::AccountComponentMetadata::mock(
            QUOTE_ASSET_COMPONENT_PATH,
        ),
    )?;

    Ok(AccountBuilder::new([11; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(PriceReaderManager::new(config))
        .with_component(quote_asset_component)
        .build_existing()?)
}

/// Builds a transaction script valuing `amount` units of `faucet_id` and asserting the result.
fn assert_quote_tx_script_code(
    faucet_id: AccountId,
    amount: u64,
    expected_is_tracked: u64,
    expected_value: u64,
) -> anyhow::Result<String> {
    let asset = FungibleAsset::new(faucet_id, amount)?;
    let asset_id_word = asset.to_id_word();
    let asset_value_word = asset.to_value_word();

    Ok(format!(
        r#"
        use miden::core::sys
        use test::oracle::quote_asset

        @transaction_script
        pub proc main
            padw padw push.{asset_value_word} push.{asset_id_word}
            # => [ASSET_ID, ASSET_VALUE, pad(8)]

            call.quote_asset::quote_asset_value
            # => [is_tracked, value_in_quote, pad(14)]

            push.{expected_is_tracked} assert_eq.err="unexpected is_tracked"
            push.{expected_value} assert_eq.err="unexpected value_in_quote"
            # => [pad(14)]

            exec.sys::truncate_stack
        end
        "#
    ))
}

/// Builds a transaction script calling `configure_feed` with `expected_quote` as the quote unit the
/// feed is asserted to publish in.
fn configure_feed_tx_script_code(feed: &Account, expected_quote: QuoteId) -> String {
    let get_price_root = *PriceFeed::get_price_root().mast_root();
    let get_quote_id_root = *PriceFeed::get_quote_id_root().mast_root();
    let quote_word = expected_quote.as_word();
    let feed_id_prefix = feed.id().prefix().as_felt();
    let feed_id_suffix = feed.id().suffix();

    format!(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_reader_manager

        @transaction_script
        pub proc main
            push.{feed_id_prefix} push.{feed_id_suffix}
            push.{quote_word} push.{get_quote_id_root} push.{get_price_root}
            # => [GET_PRICE_PROC_ROOT, GET_QUOTE_ID_PROC_ROOT, QUOTE_ID, feed_id_suffix,
            #     feed_id_prefix, ...]

            call.price_reader_manager::configure_feed

            exec.sys::truncate_stack
        end
        "#
    )
}

/// Runs a valuation transaction against a freshly built feed/reader pair.
async fn run_quote(
    entry: PriceEntry,
    quote_exponent: u32,
    max_age_secs: u32,
    untracked_policy: UntrackedAssetPolicy,
    faucet_id: AccountId,
    amount: u64,
    expected_is_tracked: u64,
    expected_value: u64,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let component_code = quote_asset_component_code()?;
    let feed = feed_account(entry)?;
    let reader = reader_account(
        &feed,
        quote_exponent,
        max_age_secs,
        untracked_policy,
        component_code.clone(),
    )?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(component_code.as_package())?
        .compile_tx_script(assert_quote_tx_script_code(
            faucet_id,
            amount,
            expected_is_tracked,
            expected_value,
        )?)?;

    let mut builder = MockChain::builder();
    builder.add_account(feed.clone())?;
    builder.add_account(reader.clone())?;
    let mock_chain = builder.build()?;

    let foreign_feed = mock_chain.get_foreign_account_inputs(feed.id())?;

    Ok(mock_chain
        .build_transaction(reader.id())
        .foreign_accounts([foreign_feed])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await)
}

// TESTS
// ================================================================================================

/// The feed returns a unit price; the reader is what multiplies by the amount. Valuing 10 units at
/// a price of 1200 with matching exponents therefore yields 12000, not 1200.
#[tokio::test]
async fn quote_multiplies_the_unit_price_by_the_amount() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    run_quote(entry, 2, 3_600, UntrackedAssetPolicy::Omit, priced_faucet()?, 10, 1, 12_000)
        .await??;

    Ok(())
}

/// A feed publishing at a smaller exponent than the reader's is scaled up, so values from feeds
/// with different exponents remain comparable.
#[tokio::test]
async fn quote_scales_up_to_the_configured_exponent() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    run_quote(
        entry,
        6,
        3_600,
        UntrackedAssetPolicy::Omit,
        priced_faucet()?,
        10,
        1,
        120_000_000,
    )
    .await??;

    Ok(())
}

/// A feed publishing at a larger exponent is scaled down, truncating toward zero.
#[tokio::test]
async fn quote_scales_down_to_the_configured_exponent() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 6, MockChain::TIMESTAMP_START_SECS)?;
    run_quote(entry, 2, 3_600, UntrackedAssetPolicy::Omit, priced_faucet()?, 10, 1, 1).await??;

    Ok(())
}

/// Under the omit policy an asset the feed does not track is reported as untracked and valued at
/// zero, rather than aborting the transaction.
#[tokio::test]
async fn an_untracked_asset_is_omitted_under_the_omit_policy() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    run_quote(entry, 2, 3_600, UntrackedAssetPolicy::Omit, unpriced_faucet()?, 10, 0, 0).await??;

    Ok(())
}

/// Under the reject policy the same asset aborts the transaction, so a caller that cannot tolerate
/// silently unpriced assets is not left summing zeros.
#[tokio::test]
async fn an_untracked_asset_is_rejected_under_the_reject_policy() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let result =
        run_quote(entry, 2, 3_600, UntrackedAssetPolicy::Reject, unpriced_faucet()?, 10, 0, 0)
            .await?;

    assert_transaction_executor_error!(result, ERR_PRICE_READER_UNTRACKED_ASSET_REJECTED);

    Ok(())
}

/// A price older than the configured maximum age aborts rather than being used. This is the reader
/// half of the staleness defence: the feed's own expiration delta bounds how far the reference
/// block may lag, but says nothing about a feed that stopped publishing.
#[tokio::test]
async fn a_stale_price_is_rejected() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS - 7_200)?;
    let result =
        run_quote(entry, 2, 3_600, UntrackedAssetPolicy::Omit, priced_faucet()?, 10, 1, 12_000)
            .await?;

    assert_transaction_executor_error!(result, ERR_PRICE_READER_PRICE_STALE);

    Ok(())
}

/// The component seeds the config map under the reserved keys the MASM reads.
#[test]
fn component_seeds_the_reader_config() -> anyhow::Result<()> {
    use miden_protocol::account::StorageMapKey;

    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let feed = feed_account(entry)?;
    let reader = reader_account(
        &feed,
        6,
        3_600,
        UntrackedAssetPolicy::Reject,
        quote_asset_component_code()?,
    )?;

    let storage = reader.storage();
    let config_slot = PriceReaderManager::config_slot();

    assert_eq!(
        storage.get_map_item(
            config_slot,
            StorageMapKey::new(PriceReaderManager::config_key_quote())
        )?,
        usd()?.as_word()
    );
    assert_eq!(
        storage.get_map_item(
            config_slot,
            StorageMapKey::new(PriceReaderManager::config_key_params())
        )?,
        Word::from([6u32, 3_600, 1, 0])
    );
    assert_eq!(
        storage.get_map_item(
            config_slot,
            StorageMapKey::new(PriceReaderManager::config_key_get_price_proc_root())
        )?,
        *PriceFeed::get_price_root().mast_root()
    );

    Ok(())
}

/// A faucet mapped to another key is looked up under that key, which is how a feed that publishes
/// under its own identifiers rather than faucet ids is supported.
#[tokio::test]
async fn a_feed_price_key_override_redirects_the_lookup() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let component_code = quote_asset_component_code()?;
    let feed = feed_account(entry)?;

    // the feed only publishes for `priced_faucet`, so without the override `unpriced_faucet` reads
    // back as untracked
    let overrides =
        BTreeMap::from([(unpriced_faucet()?, FeedPriceKey::from_faucet_id(priced_faucet()?))]);
    let reader = reader_account_with_price_keys(
        &feed,
        2,
        3_600,
        UntrackedAssetPolicy::Reject,
        component_code.clone(),
        overrides,
    )?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(component_code.as_package())?
        .compile_tx_script(assert_quote_tx_script_code(unpriced_faucet()?, 10, 1, 12_000)?)?;

    let mut builder = MockChain::builder();
    builder.add_account(feed.clone())?;
    builder.add_account(reader.clone())?;
    let mock_chain = builder.build()?;

    let foreign_feed = mock_chain.get_foreign_account_inputs(feed.id())?;

    mock_chain
        .build_transaction(reader.id())
        .foreign_accounts([foreign_feed])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// `configure_feed` verifies the feed's quote unit over FPI before writing, so a reader can never
/// be pointed at a feed quoting in a different unit than the one its thresholds are expressed in.
#[tokio::test]
async fn configure_feed_rejects_a_quote_mismatch() -> anyhow::Result<()> {
    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let feed = feed_account(entry)?;
    let reader =
        reader_account(&feed, 2, 3_600, UntrackedAssetPolicy::Omit, quote_asset_component_code()?)?;

    let tx_script = CodeBuilder::default()
        .compile_tx_script(configure_feed_tx_script_code(&feed, QuoteId::from_symbol("EUR")?))?;

    let mut builder = MockChain::builder();
    builder.add_account(feed.clone())?;
    builder.add_account(reader.clone())?;
    let mock_chain = builder.build()?;

    let foreign_feed = mock_chain.get_foreign_account_inputs(feed.id())?;

    let result = mock_chain
        .build_transaction(reader.id())
        .foreign_accounts([foreign_feed])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PRICE_READER_QUOTE_MISMATCH);

    Ok(())
}

/// `configure_feed` writes the feed account id, the `get_price` root and the quote unit when the
/// feed's quote matches.
#[tokio::test]
async fn configure_feed_writes_the_config() -> anyhow::Result<()> {
    use miden_protocol::account::StorageMapKey;

    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let feed = feed_account(entry)?;

    // start from a reader with no feed attached, so the write is observable
    let unconfigured = PriceReaderConfig::builder()
        .quote_id(usd()?)
        .quote_exponent(2)
        .max_age_secs(3_600)
        .build();
    let reader = AccountBuilder::new([12; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(PriceReaderManager::new(unconfigured))
        .build_existing()?;

    let tx_script =
        CodeBuilder::default().compile_tx_script(configure_feed_tx_script_code(&feed, usd()?))?;

    let mut builder = MockChain::builder();
    builder.add_account(feed.clone())?;
    builder.add_account(reader.clone())?;
    let mut mock_chain = builder.build()?;

    let foreign_feed = mock_chain.get_foreign_account_inputs(feed.id())?;

    let executed = mock_chain
        .build_transaction(reader.id())
        .foreign_accounts([foreign_feed])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    let storage = mock_chain.committed_account(reader.id())?.storage().clone();
    let config_slot = PriceReaderManager::config_slot();

    assert_eq!(
        storage.get_map_item(
            config_slot,
            StorageMapKey::new(PriceReaderManager::config_key_feed_account_id())
        )?,
        FeedPriceKey::from_faucet_id(feed.id()).as_word()
    );
    assert_eq!(
        storage.get_map_item(
            config_slot,
            StorageMapKey::new(PriceReaderManager::config_key_get_price_proc_root())
        )?,
        *PriceFeed::get_price_root().mast_root()
    );
    assert_eq!(
        storage.get_map_item(
            config_slot,
            StorageMapKey::new(PriceReaderManager::config_key_quote())
        )?,
        usd()?.as_word()
    );

    Ok(())
}

/// `set_reader_params` rewrites the quote exponent, staleness bound and untracked policy in place.
#[tokio::test]
async fn set_reader_params_writes_the_params() -> anyhow::Result<()> {
    use miden_protocol::account::StorageMapKey;

    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let feed = feed_account(entry)?;
    let reader =
        reader_account(&feed, 2, 3_600, UntrackedAssetPolicy::Omit, quote_asset_component_code()?)?;

    let tx_script = CodeBuilder::default().compile_tx_script(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_reader_manager

        @transaction_script
        pub proc main
            push.1 push.60 push.8
            # => [quote_exponent, max_age_secs, untracked_policy, ...]

            call.price_reader_manager::set_reader_params

            exec.sys::truncate_stack
        end
        "#,
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(feed.clone())?;
    builder.add_account(reader.clone())?;
    let mut mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(reader.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        mock_chain.committed_account(reader.id())?.storage().get_map_item(
            PriceReaderManager::config_slot(),
            StorageMapKey::new(PriceReaderManager::config_key_params())
        )?,
        Word::from([8u32, 60, 1, 0])
    );

    Ok(())
}

/// `set_asset_feed_price_key` writes the override the reader resolves lookups through.
#[tokio::test]
async fn set_asset_feed_price_key_writes_the_override() -> anyhow::Result<()> {
    use miden_protocol::account::StorageMapKey;

    let entry = PriceEntry::new(Felt::from(1_200u32), 2, MockChain::TIMESTAMP_START_SECS)?;
    let feed = feed_account(entry)?;
    let reader =
        reader_account(&feed, 2, 3_600, UntrackedAssetPolicy::Omit, quote_asset_component_code()?)?;

    let faucet_id_word = FeedPriceKey::from_faucet_id(unpriced_faucet()?).as_word();
    let feed_price_key = FeedPriceKey::from_faucet_id(priced_faucet()?).as_word();
    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_reader_manager

        @transaction_script
        pub proc main
            push.{feed_price_key} push.{faucet_id_word}
            # => [FAUCET_ID, FEED_PRICE_KEY, ...]

            call.price_reader_manager::set_asset_feed_price_key

            exec.sys::truncate_stack
        end
        "#
    ))?;

    let mut builder = MockChain::builder();
    builder.add_account(feed.clone())?;
    builder.add_account(reader.clone())?;
    let mut mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(reader.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        mock_chain.committed_account(reader.id())?.storage().get_map_item(
            PriceReaderManager::price_keys_slot(),
            StorageMapKey::new(faucet_id_word)
        )?,
        feed_price_key
    );

    Ok(())
}
