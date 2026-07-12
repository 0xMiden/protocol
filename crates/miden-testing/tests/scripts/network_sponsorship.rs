use miden_protocol::Word;
use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::errors::standards::{
    ERR_NETWORK_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER,
    ERR_NETWORK_SPONSORSHIP_RECLAIM_DISABLED,
    ERR_NETWORK_SPONSORSHIP_RECLAIM_HEIGHT_NOT_REACHED,
};
use miden_standards::note::NetworkSponsorshipNote;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

const FEE_AMOUNT: u64 = 500;

fn auth() -> Auth {
    Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    }
}

/// The cast for every test below: a network account that the sponsorship targets, the sponsor who
/// created it, an unrelated third party, the fee-unaware feature note, and the sponsorship bound to
/// it.
struct Fixture {
    mock_chain: MockChain,
    network_account: Account,
    sponsor: Account,
    stranger: Account,
    feature_note: Note,
    sponsorship_note: Note,
    fee_asset: Asset,
}

/// Builds the fixture with the given reclaim height (`None` disables reclaim).
fn setup(reclaim_height: Option<BlockNumber>) -> anyhow::Result<Fixture> {
    let fee_asset: Asset = FungibleAsset::mock(FEE_AMOUNT);
    let mut rng = RandomCoin::new(Word::empty());

    let mut builder = MockChain::builder();
    let network_account = builder.add_existing_wallet(auth())?;
    let sponsor = builder.add_existing_wallet(auth())?;
    let stranger = builder.add_existing_wallet(auth())?;

    // The feature note is completely fee-unaware: it carries no fee and knows nothing about the
    // sponsorship. P2ANY stands in for a real network note here.
    let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

    let sponsorship_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(network_account.id())?
            .feature_note_id(feature_note.id())
            .asset(fee_asset)
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

/// The happy path: the target consumes the sponsorship alongside the feature note it pays for.
#[tokio::test]
async fn target_consumes_sponsorship_with_feature_note() -> anyhow::Result<()> {
    let f = setup(None)?;

    let executed = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .authenticated_input_note(f.feature_note.id())
        .build()?
        .execute()
        .await?;

    let mut network_account = f.network_account;
    network_account.apply_patch(executed.account_patch())?;
    assert_eq!(
        network_account.vault().get_balance(f.fee_asset.id())?.as_u64(),
        FEE_AMOUNT,
        "the network account should receive the sponsored fee",
    );

    Ok(())
}

/// The sponsorship cannot be consumed on its own, even by its target.
///
/// This is the check that protects the sponsor. Without it, the network account (or the transaction
/// builder that assembles the transaction) could pocket the fee and never run the feature note.
/// A target without the feature note gets no special treatment: it falls into the reclaim path,
/// which is disabled here.
#[tokio::test]
async fn target_cannot_consume_sponsorship_without_feature_note() -> anyhow::Result<()> {
    let f = setup(None)?;

    let result = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NETWORK_SPONSORSHIP_RECLAIM_DISABLED);

    Ok(())
}

/// Even with reclaim enabled and its height reached, a target without the feature note cannot take
/// the assets: the reclaim path returns them to the reclaimer, and the target is not the reclaimer.
#[tokio::test]
async fn target_without_feature_note_is_not_the_reclaimer() -> anyhow::Result<()> {
    let f = setup(Some(BlockNumber::from(1u32)))?;

    let result = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_NETWORK_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER
    );

    Ok(())
}

/// The order in which the two notes are consumed does not matter.
///
/// The presence check reads input notes by index, which the prologue has already materialized, so
/// it does not depend on the feature note having executed first.
#[tokio::test]
async fn note_order_does_not_matter() -> anyhow::Result<()> {
    let f = setup(None)?;

    f.mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.feature_note.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// A stranger cannot take the sponsorship: they are not the target, so they land on the reclaim
/// path, and they are not the sponsor either.
#[tokio::test]
async fn stranger_cannot_consume_sponsorship() -> anyhow::Result<()> {
    let f = setup(Some(BlockNumber::from(1u32)))?;

    let result = f
        .mock_chain
        .build_transaction(f.stranger.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .authenticated_input_note(f.feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_NETWORK_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER
    );

    Ok(())
}

/// The sponsor can reclaim the note once the reclaim height is reached.
///
/// This path is load-bearing: if the bound feature note is consumed by some other transaction, the
/// presence check can never pass again, and reclaim is the only way to recover the assets.
#[tokio::test]
async fn sponsor_reclaims_after_reclaim_height() -> anyhow::Result<()> {
    let f = setup(Some(BlockNumber::from(1u32)))?;
    assert!(f.mock_chain.latest_block_header().block_num() >= BlockNumber::from(1u32));

    let executed = f
        .mock_chain
        .build_transaction(f.sponsor.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await?;

    let mut sponsor = f.sponsor;
    sponsor.apply_patch(executed.account_patch())?;
    assert_eq!(
        sponsor.vault().get_balance(f.fee_asset.id())?.as_u64(),
        FEE_AMOUNT,
        "the sponsor should get the unused fee back",
    );

    Ok(())
}

/// The sponsor cannot reclaim before the reclaim height.
#[tokio::test]
async fn sponsor_cannot_reclaim_before_reclaim_height() -> anyhow::Result<()> {
    let f = setup(Some(BlockNumber::from(1_000u32)))?;

    let result = f
        .mock_chain
        .build_transaction(f.sponsor.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NETWORK_SPONSORSHIP_RECLAIM_HEIGHT_NOT_REACHED);

    Ok(())
}

/// A sponsorship whose sender is also its target, as in a self-spawning chain sponsoring its own
/// next hop, bound to a feature note that is never consumed.
fn self_targeted_fixture(reclaim_height: u32) -> anyhow::Result<(MockChain, Account, Note, Asset)> {
    let fee_asset: Asset = FungibleAsset::mock(FEE_AMOUNT);
    let mut rng = RandomCoin::new(Word::empty());

    let mut builder = MockChain::builder();
    let network_account = builder.add_existing_wallet(auth())?;
    let feature_note = builder.add_p2any_note(network_account.id(), NoteType::Public, [])?;

    let sponsorship_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(network_account.id())
            .target_account(network_account.id())?
            .feature_note_id(feature_note.id())
            .asset(fee_asset)
            .reclaim_height(BlockNumber::from(reclaim_height))
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    Ok((mock_chain, network_account, sponsorship_note, fee_asset))
}

/// A self-targeted sponsorship falls back to the reclaim path when its feature note cannot be
/// presented: the target consuming without the feature note is valid only as the sponsor.
#[tokio::test]
async fn self_targeted_sponsor_reclaims_without_feature_note() -> anyhow::Result<()> {
    let (mock_chain, network_account, sponsorship_note, fee_asset) = self_targeted_fixture(1)?;

    let executed = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await?;

    let mut network_account = network_account;
    network_account.apply_patch(executed.account_patch())?;
    assert_eq!(network_account.vault().get_balance(fee_asset.id())?.as_u64(), FEE_AMOUNT);

    Ok(())
}

/// The self-target fallback still honors the reclaim height.
#[tokio::test]
async fn self_targeted_sponsor_cannot_reclaim_before_height() -> anyhow::Result<()> {
    let (mock_chain, network_account, sponsorship_note, _) = self_targeted_fixture(1_000)?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NETWORK_SPONSORSHIP_RECLAIM_HEIGHT_NOT_REACHED);

    Ok(())
}

/// With reclaim disabled, not even the sponsor can take the note back.
#[tokio::test]
async fn sponsor_cannot_reclaim_when_reclaim_is_disabled() -> anyhow::Result<()> {
    let f = setup(None)?;

    let result = f
        .mock_chain
        .build_transaction(f.sponsor.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NETWORK_SPONSORSHIP_RECLAIM_DISABLED);

    Ok(())
}

/// Builds a fixture whose sponsorship names the stranger as an explicit reclaimer, distinct from
/// the sender.
fn named_reclaimer_setup(reclaim_height: BlockNumber) -> anyhow::Result<Fixture> {
    let fee_asset: Asset = FungibleAsset::mock(FEE_AMOUNT);
    let mut rng = RandomCoin::new(Word::empty());

    let mut builder = MockChain::builder();
    let network_account = builder.add_existing_wallet(auth())?;
    let sponsor = builder.add_existing_wallet(auth())?;
    let stranger = builder.add_existing_wallet(auth())?;

    let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

    let sponsorship_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(network_account.id())?
            .feature_note_id(feature_note.id())
            .asset(fee_asset)
            .reclaimer(stranger.id())
            .reclaim_height(reclaim_height)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

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

/// Reclaim keys on the stored reclaimer, not the sender: a named reclaimer distinct from the sender
/// can reclaim the note once the reclaim height is reached.
#[tokio::test]
async fn named_reclaimer_reclaims_after_reclaim_height() -> anyhow::Result<()> {
    let f = named_reclaimer_setup(BlockNumber::from(1u32))?;

    let executed = f
        .mock_chain
        .build_transaction(f.stranger.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await?;

    let mut reclaimer = f.stranger;
    reclaimer.apply_patch(executed.account_patch())?;
    assert_eq!(
        reclaimer.vault().get_balance(f.fee_asset.id())?.as_u64(),
        FEE_AMOUNT,
        "the named reclaimer should get the unused fee back",
    );

    Ok(())
}

/// The sender cannot reclaim once a different reclaimer is named: this is what makes the reclaimer,
/// not the sender, the authority.
#[tokio::test]
async fn sender_cannot_reclaim_when_a_different_reclaimer_is_named() -> anyhow::Result<()> {
    let f = named_reclaimer_setup(BlockNumber::from(1u32))?;

    let result = f
        .mock_chain
        .build_transaction(f.sponsor.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_NETWORK_SPONSORSHIP_RECLAIM_ACCT_IS_NOT_RECLAIMER
    );

    Ok(())
}
