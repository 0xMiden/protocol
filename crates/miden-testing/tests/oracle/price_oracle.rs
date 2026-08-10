//! Tests for [`miden_standards::account::oracle::PriceOracle`], the user-facing interface of the
//! price oracle standard.
//!
//! Every test reaches `get_conversion_rate` the way a consumer does: over FPI, by the wrapper's
//! MAST root. That root is also pinned here, because keeping it stable across implementation
//! changes is the reason the wrapper exists.

use miden_protocol::Felt;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_standards::account::access::Authority;
use miden_standards::account::oracle::{PriceEntry, PriceFeed, PriceOracle};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

use super::common::{
    asset_id_of,
    consumer_account,
    oracle_account,
    source_faucet,
    target_faucet,
    unpriced_faucet,
    usd,
};

/// Builds a transaction script asserting the rate the oracle reports for a pair.
fn assert_rate_tx_script_code(
    oracle_id: AccountId,
    source_asset_id: miden_protocol::Word,
    target_asset_id: miden_protocol::Word,
    expected_num: u64,
    expected_den: u64,
    expected_timestamp: u64,
) -> String {
    format!(
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
            # => [num, den, timestamp, pad(13)]

            push.{expected_num} assert_eq.err="unexpected rate numerator"
            push.{expected_den} assert_eq.err="unexpected rate denominator"
            push.{expected_timestamp} assert_eq.err="unexpected rate timestamp"
            # => [pad(13)]

            exec.sys::truncate_stack
        end
        "#,
        rate_root = *PriceOracle::get_conversion_rate_root().mast_root(),
        oracle_prefix = oracle_id.prefix().as_felt(),
        oracle_suffix = oracle_id.suffix(),
    )
}

/// Runs a rate assertion against an oracle publishing the given prices.
async fn assert_rate(
    prices: &[(AccountId, PriceEntry)],
    source: AccountId,
    target: AccountId,
    expected_num: u64,
    expected_den: u64,
    expected_timestamp: u64,
) -> anyhow::Result<()> {
    let oracle = oracle_account(prices)?;
    let consumer = consumer_account([32; 32])?;

    let tx_script = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        asset_id_of(source)?,
        asset_id_of(target)?,
        expected_num,
        expected_den,
        expected_timestamp,
    ))?;

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

/// The rate between two priced assets is their price ratio, with each leg's exponent applied to the
/// other side so the quote unit cancels: `(p_src * 10^e_tgt) / (p_tgt * 10^e_src)`.
#[tokio::test]
async fn the_rate_between_two_priced_assets_is_their_price_ratio() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;

    // source at 1_500 with exponent 2, target at 3 with exponent 0: one source unit is worth 500
    // target units, expressed as 1_500 / 3.
    assert_rate(
        &[
            (source_faucet()?, PriceEntry::new(Felt::from(1_500u32), 2, now)?),
            (target_faucet()?, PriceEntry::new(Felt::from(3u32), 0, now)?),
        ],
        source_faucet()?,
        target_faucet()?,
        1_500,
        300,
        u64::from(now),
    )
    .await
}

/// A rate is only as fresh as its stalest leg, so the older of the two publication timestamps is
/// what the oracle reports.
#[tokio::test]
async fn the_reported_timestamp_is_the_stalest_leg() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;
    let older = now - 900;

    assert_rate(
        &[
            (source_faucet()?, PriceEntry::new(Felt::from(2u32), 0, now)?),
            (target_faucet()?, PriceEntry::new(Felt::from(1u32), 0, older)?),
        ],
        source_faucet()?,
        target_faucet()?,
        2,
        1,
        u64::from(older),
    )
    .await
}

/// Converting an asset into itself needs no price at all and never goes stale.
#[tokio::test]
async fn an_asset_converts_into_itself_at_one_to_one() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;

    assert_rate(
        &[(source_faucet()?, PriceEntry::new(Felt::from(7u32), 3, now)?)],
        source_faucet()?,
        source_faucet()?,
        1,
        1,
        u64::from(now),
    )
    .await
}

/// A pair the oracle cannot price yields a zero denominator rather than a failure, so a caller
/// valuing many assets can decide what an unpriceable one means to it.
#[tokio::test]
async fn an_unpriceable_pair_yields_a_zero_denominator() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;

    assert_rate(
        &[(source_faucet()?, PriceEntry::new(Felt::from(2u32), 0, now)?)],
        source_faucet()?,
        unpriced_faucet()?,
        0,
        0,
        0,
    )
    .await
}

/// The interface's MAST root is the address consumers resolve against, so it must survive changes
/// to the pricing implementation and to the rest of the standard.
///
/// If this fails, `get_conversion_rate`'s body changed. That is a breaking change for every
/// consumer that already resolved the old root, not a value to update in passing.
#[test]
fn the_interface_root_is_stable() {
    let root = *PriceOracle::get_conversion_rate_root().mast_root();

    assert_eq!(
        root.to_hex(),
        PINNED_GET_CONVERSION_RATE_ROOT,
        "the price oracle interface root changed; see the test documentation"
    );
}

/// The MAST root of `price_oracle::get_conversion_rate`.
const PINNED_GET_CONVERSION_RATE_ROOT: &str =
    "0x6721cd98b89feb04648ffa02212a20d30683230b8af554f17d2ad5e813569109";

/// The feed registers itself as the oracle's implementation, so the wrapper dispatches to it.
#[test]
fn the_feed_is_registered_as_the_oracle_implementation() -> anyhow::Result<()> {
    let oracle = oracle_account(&[])?;

    assert_eq!(
        oracle.storage().get_item(PriceOracle::implementation_slot())?,
        *PriceFeed::compute_conversion_rate_root().mast_root()
    );

    Ok(())
}

/// A second implementation, used to show that swapping the pricing behind the wrapper leaves the
/// address consumers resolve against untouched.
const ALTERNATIVE_IMPL_PATH: &str = "test::oracle::alternative";

const ALTERNATIVE_IMPL_CODE: &str = r#"
    use miden::core::sys
    use miden::protocol::tx

    #! Inputs:  [SOURCE_ASSET_ID, TARGET_ASSET_ID, pad(8)]
    #! Outputs: [num, den, timestamp, pad(13)]
    #!
    #! Invocation: dyncall
    @account_procedure
    pub proc compute_conversion_rate
        dropw dropw
        # => [pad(8)]

        exec.tx::get_block_timestamp push.1 push.7
        # => [num = 7, den = 1, timestamp, pad(8)]

        exec.sys::truncate_stack
    end
"#;

/// Builds an oracle carrying both the feed and the alternative implementation, with the feed
/// active.
fn swappable_oracle_account(
    prices: &[(AccountId, PriceEntry)],
    alternative: &AccountComponentCode,
) -> anyhow::Result<Account> {
    let mut feed = PriceFeed::new(usd()?);
    for (faucet_id, entry) in prices {
        feed = feed.with_price(*faucet_id, *entry);
    }

    let alternative_component = AccountComponent::new(
        alternative.clone(),
        Vec::new(),
        AccountComponentMetadata::mock(ALTERNATIVE_IMPL_PATH),
    )?;

    Ok(AccountBuilder::new([35; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(feed)
        .with_component(
            PriceOracle::new().with_implementation(PriceFeed::compute_conversion_rate_root()),
        )
        .with_component(alternative_component)
        .build_existing()?)
}

/// Replacing the pricing implementation leaves the interface's MAST root untouched, so a consumer
/// that resolved it before the swap keeps reaching the oracle afterwards and sees the new pricing.
///
/// This is the property the wrapper exists for. Pinning the root in isolation does not demonstrate
/// it; running the same root across a swap does.
#[tokio::test]
async fn swapping_the_implementation_keeps_the_interface_reachable() -> anyhow::Result<()> {
    let now = MockChain::TIMESTAMP_START_SECS;
    let alternative = CodeBuilder::default()
        .compile_component_code(ALTERNATIVE_IMPL_PATH, ALTERNATIVE_IMPL_CODE)?;
    let alternative_root = alternative
        .get_procedure_root_by_path("test::oracle::alternative::compute_conversion_rate")
        .expect("component should export compute_conversion_rate");

    let prices = [
        (source_faucet()?, PriceEntry::new(Felt::from(1_500u32), 2, now)?),
        (target_faucet()?, PriceEntry::new(Felt::from(3u32), 0, now)?),
    ];
    let oracle = swappable_oracle_account(&prices, &alternative)?;
    let consumer = consumer_account([36; 32])?;

    let mut builder = MockChain::builder();
    builder.add_account(oracle.clone())?;
    builder.add_account(consumer.clone())?;
    let mut mock_chain = builder.build()?;

    // the feed-derived rate, read through the wrapper
    let before = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        asset_id_of(source_faucet()?)?,
        asset_id_of(target_faucet()?)?,
        1_500,
        300,
        u64::from(now),
    ))?;
    let foreign_oracle = mock_chain.get_foreign_account_inputs(oracle.id())?;
    mock_chain
        .build_transaction(consumer.id())
        .foreign_accounts([foreign_oracle])
        .tx_script(before)
        .build()?
        .execute()
        .await?;

    // swap the implementation
    let swap = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::core::sys
        use miden::standards::oracle::price_oracle

        @transaction_script
        pub proc main
            push.{alternative_root}
            # => [IMPLEMENTATION_ROOT, ...]

            call.price_oracle::set_implementation

            exec.sys::truncate_stack
        end
        "#,
        alternative_root = *alternative_root.mast_root(),
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
            .get_item(PriceOracle::implementation_slot())?,
        *alternative_root.mast_root(),
        "set_implementation should have registered the alternative implementation"
    );

    // the same wrapper root now answers with the alternative implementation's pricing
    let after = CodeBuilder::default().compile_tx_script(assert_rate_tx_script_code(
        oracle.id(),
        asset_id_of(source_faucet()?)?,
        asset_id_of(target_faucet()?)?,
        7,
        1,
        u64::from(mock_chain.latest_block_header().timestamp()),
    ))?;
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
