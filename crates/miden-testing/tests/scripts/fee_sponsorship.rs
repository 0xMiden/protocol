use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME;
use miden_protocol::note::{Note, NoteAssets, NoteTag, NoteType, PartialNoteMetadata};
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_SPONSORSHIP_MUST_CONTAIN_EXACTLY_ONE_ASSET,
    ERR_FEE_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER,
    ERR_FEE_SPONSORSHIP_RECLAIM_DISABLED,
    ERR_FEE_SPONSORSHIP_RECLAIM_HEIGHT_NOT_REACHED,
};
use miden_standards::note::{FeeSponsorshipNote, FeeSponsorshipNoteStorage};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

const FEE_AMOUNT: u64 = 500;

/// Compiles a transaction script that moves `fee_asset` into the executing account's vault.
///
/// On the sponsorship path the note script leaves the sponsored assets in place, so the consuming
/// transaction has to collect them itself. This script stands in for the account's fee-collection
/// logic (for a network account, typically its auth procedure).
fn collect_fee_tx_script(fee_asset: Asset) -> anyhow::Result<TransactionScript> {
    let src = format!(
        "
        use miden::standards::wallets::basic as wallet

        @transaction_script
        pub proc main
            push.{asset_value}
            push.{asset_id}
            # => [ASSET_ID, ASSET_VALUE]

            padw padw swapdw
            # => [ASSET_ID, ASSET_VALUE, pad(8)]

            call.wallet::receive_asset
            # => [pad(16)]

            dropw dropw dropw dropw
        end
        ",
        asset_value = fee_asset.to_value_word(),
        asset_id = fee_asset.to_id_word(),
    );
    Ok(CodeBuilder::default().compile_tx_script(src)?)
}

/// Who the sponsorship names as its reclaimer.
enum Reclaimer {
    /// The reclaimer is left unset and defaults to the sender.
    Sender,
    /// The stranger is named as an explicit reclaimer, distinct from the sender.
    Stranger,
}

/// The cast for every test below: the network account the sponsorship is routed to, the sponsor who
/// created it, an unrelated third party, the fee-unaware feature note, and the sponsorship bound
/// to it.
struct Fixture {
    mock_chain: MockChain,
    network_account: Account,
    sponsor: Account,
    stranger: Account,
    feature_note: Note,
    sponsorship_note: Note,
    fee_asset: Asset,
}

/// Builds the fixture with the given reclaim height (`None` disables reclaim) and reclaimer.
fn setup(reclaim_height: Option<BlockNumber>, reclaimer: Reclaimer) -> anyhow::Result<Fixture> {
    let fee_asset: Asset = FungibleAsset::mock(FEE_AMOUNT);
    let mut rng = RandomCoin::new(Word::empty());

    let mut builder = MockChain::builder();
    let network_account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let sponsor = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let stranger = builder.add_existing_wallet(Auth::basic_ecdsa())?;

    // The feature note is completely fee-unaware: it carries no fee and knows nothing about the
    // sponsorship. P2ANY stands in for a real network note here.
    let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

    let reclaimer = match reclaimer {
        Reclaimer::Sender => None,
        Reclaimer::Stranger => Some(stranger.id()),
    };

    let sponsorship_note = Note::from(
        FeeSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(network_account.id())
            .feature_note_id(feature_note.id())
            .asset(fee_asset)
            .maybe_reclaimer(reclaimer)
            .maybe_reclaim_height(reclaim_height)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    // Advance past genesis so that a reclaim height of 1 counts as reached. Without this every
    // reclaim path would stop at the height check before reaching the checks under test.
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    Ok(Fixture {
        mock_chain,
        network_account,
        sponsor,
        stranger,
        feature_note,
        sponsorship_note,
        fee_asset,
    })
}

/// The happy path: the network account consumes the sponsorship alongside the feature note it
/// pays for, collecting the fee itself since the note script leaves the assets in place.
#[tokio::test]
async fn network_account_consumes_sponsorship_with_feature_note() -> anyhow::Result<()> {
    let Fixture {
        mock_chain,
        mut network_account,
        feature_note,
        sponsorship_note,
        fee_asset,
        ..
    } = setup(None, Reclaimer::Sender)?;

    let executed = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_note.id())
        .authenticated_input_note(feature_note.id())
        .tx_script(collect_fee_tx_script(fee_asset)?)
        .build()?
        .execute()
        .await?;

    network_account.apply_patch(executed.account_patch())?;
    assert_eq!(
        network_account.vault().get_balance(fee_asset.id())?.as_u64(),
        FEE_AMOUNT,
        "the network account should receive the sponsored fee",
    );

    crate::prove_and_verify_transaction(executed).await?;

    Ok(())
}

/// The sponsorship path itself does not move the note's assets: a transaction that consumes the
/// sponsorship alongside its feature note but never collects the fee fails asset conservation in
/// the epilogue.
///
/// This pins the division of labor: collecting the fee is the consuming account's job, so the note
/// requires no wallet interface from the consuming account.
#[tokio::test]
async fn sponsor_path_leaves_assets_in_the_note() -> anyhow::Result<()> {
    let Fixture {
        mock_chain,
        network_account,
        feature_note,
        sponsorship_note,
        ..
    } = setup(None, Reclaimer::Sender)?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_note.id())
        .authenticated_input_note(feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_EPILOGUE_TOTAL_NUMBER_OF_ASSETS_MUST_STAY_THE_SAME
    );

    Ok(())
}

/// The sponsorship cannot be consumed on its own: without the feature note the script falls into
/// the reclaim path, which rejects the consumer whether reclaim is disabled or the consumer is
/// simply not the reclaimer.
///
/// This is the check that protects the sponsor. Without it, the consuming account (or the
/// transaction builder that assembles the transaction) could pocket the fee and never run the
/// feature note.
#[rstest]
#[case::reclaim_disabled(None, ERR_FEE_SPONSORSHIP_RECLAIM_DISABLED)]
#[case::not_the_reclaimer(
    Some(BlockNumber::from(1u32)),
    ERR_FEE_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER
)]
#[tokio::test]
async fn sponsorship_cannot_be_consumed_without_feature_note(
    #[case] reclaim_height: Option<BlockNumber>,
    #[case] expected_err: MasmError,
) -> anyhow::Result<()> {
    let Fixture {
        mock_chain,
        network_account,
        sponsorship_note,
        ..
    } = setup(reclaim_height, Reclaimer::Sender)?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, expected_err);

    Ok(())
}

/// The script rejects a sponsorship note that does not carry exactly one asset.
///
/// The Rust builder cannot produce such a note, so it is assembled by hand from the raw parts.
#[tokio::test]
async fn script_rejects_note_without_exactly_one_asset() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();
    let network_account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let sponsor = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

    let storage = FeeSponsorshipNoteStorage::new(feature_note.id(), sponsor.id(), None);
    let metadata = PartialNoteMetadata::new(sponsor.id(), NoteType::Public)
        .with_tag(NoteTag::with_account_target(network_account.id()));
    let assetless_sponsorship =
        Note::new(NoteAssets::default(), metadata, storage.into_recipient(rng.draw_word()));
    builder.add_output_note(RawOutputNote::Full(assetless_sponsorship.clone()));
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(assetless_sponsorship.id())
        .authenticated_input_note(feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_SPONSORSHIP_MUST_CONTAIN_EXACTLY_ONE_ASSET);

    Ok(())
}

/// The order in which the two notes are consumed does not matter.
///
/// The presence check reads input notes by index, which the prologue has already materialized, so
/// it does not depend on the feature note having executed first.
#[rstest]
#[tokio::test]
async fn note_order_does_not_matter(
    #[values(true, false)] sponsorship_first: bool,
) -> anyhow::Result<()> {
    let Fixture {
        mock_chain,
        network_account,
        feature_note,
        sponsorship_note,
        fee_asset,
        ..
    } = setup(None, Reclaimer::Sender)?;

    let (first, second) = if sponsorship_first {
        (&sponsorship_note, &feature_note)
    } else {
        (&feature_note, &sponsorship_note)
    };

    mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(first.id())
        .authenticated_input_note(second.id())
        .tx_script(collect_fee_tx_script(fee_asset)?)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Consumption rights are inherited from the feature note: the sponsorship does not restrict who
/// consumes it, so whoever may consume the feature note may claim the sponsored fee alongside it.
///
/// The P2ANY feature note used here is consumable by anyone, so the stranger collects the fee. A
/// real network feature note restricts its consumers itself (for example a note targeting the
/// network account), and the sponsorship inherits that restriction transitively.
#[tokio::test]
async fn anyone_consuming_the_feature_note_takes_the_sponsorship() -> anyhow::Result<()> {
    let Fixture {
        mock_chain,
        mut stranger,
        feature_note,
        sponsorship_note,
        fee_asset,
        ..
    } = setup(None, Reclaimer::Sender)?;

    let executed = mock_chain
        .build_transaction(stranger.id())
        .authenticated_input_note(sponsorship_note.id())
        .authenticated_input_note(feature_note.id())
        .tx_script(collect_fee_tx_script(fee_asset)?)
        .build()?
        .execute()
        .await?;

    stranger.apply_patch(executed.account_patch())?;
    assert_eq!(
        stranger.vault().get_balance(fee_asset.id())?.as_u64(),
        FEE_AMOUNT,
        "whoever consumes the feature note receives the sponsored fee",
    );

    Ok(())
}

/// A stranger consuming the sponsorship without the feature note lands on the reclaim path and is
/// rejected there.
#[tokio::test]
async fn stranger_cannot_consume_sponsorship_without_feature_note() -> anyhow::Result<()> {
    let Fixture {
        mock_chain, stranger, sponsorship_note, ..
    } = setup(Some(BlockNumber::from(1u32)), Reclaimer::Sender)?;

    let result = mock_chain
        .build_transaction(stranger.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER);

    Ok(())
}

/// The sponsor can reclaim the note once the reclaim height is reached.
///
/// This path is load-bearing: if the bound feature note is consumed by some other transaction,
/// the presence check can never pass again, and reclaim is the only way to recover the assets.
#[tokio::test]
async fn sponsor_reclaims_after_reclaim_height() -> anyhow::Result<()> {
    let Fixture {
        mock_chain,
        mut sponsor,
        sponsorship_note,
        fee_asset,
        ..
    } = setup(Some(BlockNumber::from(1u32)), Reclaimer::Sender)?;
    assert!(mock_chain.latest_block_header().block_num() >= BlockNumber::from(1u32));

    let executed = mock_chain
        .build_transaction(sponsor.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await?;

    sponsor.apply_patch(executed.account_patch())?;
    assert_eq!(
        sponsor.vault().get_balance(fee_asset.id())?.as_u64(),
        FEE_AMOUNT,
        "the sponsor should get the unused fee back",
    );

    Ok(())
}

/// The sponsor cannot reclaim before the reclaim height.
#[tokio::test]
async fn sponsor_cannot_reclaim_before_reclaim_height() -> anyhow::Result<()> {
    let Fixture {
        mock_chain, sponsor, sponsorship_note, ..
    } = setup(Some(BlockNumber::from(1_000u32)), Reclaimer::Sender)?;

    let result = mock_chain
        .build_transaction(sponsor.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_SPONSORSHIP_RECLAIM_HEIGHT_NOT_REACHED);

    Ok(())
}

/// With reclaim disabled, not even the sponsor can take the note back.
#[tokio::test]
async fn sponsor_cannot_reclaim_when_reclaim_is_disabled() -> anyhow::Result<()> {
    let Fixture {
        mock_chain, sponsor, sponsorship_note, ..
    } = setup(None, Reclaimer::Sender)?;

    let result = mock_chain
        .build_transaction(sponsor.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_SPONSORSHIP_RECLAIM_DISABLED);

    Ok(())
}

/// Reclaim keys on the stored reclaimer, not the sender: a named reclaimer distinct from the sender
/// can reclaim the note once the reclaim height is reached.
#[tokio::test]
async fn named_reclaimer_reclaims_after_reclaim_height() -> anyhow::Result<()> {
    let Fixture {
        mock_chain,
        mut stranger,
        sponsorship_note,
        fee_asset,
        ..
    } = setup(Some(BlockNumber::from(1u32)), Reclaimer::Stranger)?;

    let executed = mock_chain
        .build_transaction(stranger.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await?;

    stranger.apply_patch(executed.account_patch())?;
    assert_eq!(
        stranger.vault().get_balance(fee_asset.id())?.as_u64(),
        FEE_AMOUNT,
        "the named reclaimer should get the unused fee back",
    );

    Ok(())
}

/// The sender cannot reclaim once a different reclaimer is named: this is what makes the reclaimer,
/// not the sender, the authority.
#[tokio::test]
async fn sender_cannot_reclaim_when_a_different_reclaimer_is_named() -> anyhow::Result<()> {
    let Fixture {
        mock_chain, sponsor, sponsorship_note, ..
    } = setup(Some(BlockNumber::from(1u32)), Reclaimer::Stranger)?;

    let result = mock_chain
        .build_transaction(sponsor.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER);

    Ok(())
}
