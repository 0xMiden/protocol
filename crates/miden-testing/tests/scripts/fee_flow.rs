//! End-to-end tests of the sponsorship fee flow (approach C of discussion #2968).
//!
//! A feature note stays entirely fee-unaware. Its fee travels in a separate sponsorship note that
//! names it by note ID. The network account's auth procedure asserts every feature note it consumed
//! was covered, keeps the application portion, and forwards the protocol portion to the batch
//! builder in a FEE note that anyone may consume.

use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteId, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::Authority;
use miden_standards::account::auth::AuthNetworkAccountWithFees;
use miden_standards::account::fees::{FeeManager, FeeScheduleEntry};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP,
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
};
use miden_standards::note::{NetworkSponsorshipNote, P2idNote};
use miden_testing::{
    Auth,
    MockChain,
    MockChainBuilder,
    assert_note_created,
    assert_transaction_executor_error,
};
use rstest::rstest;

const APP_FEE: u64 = 30;
const PROTOCOL_FEE: u64 = 12;
const BUSINESS_AMOUNT: u64 = 777;

fn fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, amount)?.into())
}

fn business_asset() -> anyhow::Result<Asset> {
    Ok(
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, BUSINESS_AMOUNT)?
            .into(),
    )
}

struct Fixture {
    mock_chain: MockChain,
    network_account: Account,
    feature_note: Note,
    sponsorship_note: Note,
}

/// Adds the fee-managed network account: allowlist + fee auth, `BasicWallet`, `Authority`, and
/// `FeeManager` pricing the fee-unaware P2ID feature note.
fn add_network_account(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    let fee_manager = FeeManager::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?)?
        // The feature note is a plain P2ID: it knows nothing about fees.
        .with_fee(P2idNote::script_root(), FeeScheduleEntry::new(APP_FEE, PROTOCOL_FEE)?);

    let auth =
        AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::from([P2idNote::script_root()]))?;

    let network_account = AccountBuilder::new([7u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_component(fee_manager)
        .build_existing()?;
    builder.add_account(network_account.clone())?;

    Ok(network_account)
}

struct MultiFixture {
    mock_chain: MockChain,
    network_account: Account,
    feature_notes: Vec<Note>,
    sponsorship_notes: Vec<Note>,
}

/// Builds a fee-managed network account, `num_feature_notes` fee-unaware P2ID feature notes
/// targeted at it, and one sponsorship note per `(feature_idx, assets)` entry, bound to the
/// feature note at `feature_idx` and carrying `assets`.
fn setup_multi(
    num_feature_notes: usize,
    sponsorships: &[(usize, Vec<Asset>)],
) -> anyhow::Result<MultiFixture> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();

    let network_account = add_network_account(&mut builder)?;
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

    let mut feature_notes = Vec::new();
    for _ in 0..num_feature_notes {
        feature_notes.push(builder.add_p2id_note(
            sponsor.id(),
            network_account.id(),
            &[business_asset()?],
            NoteType::Public,
        )?);
    }

    let mut sponsorship_notes = Vec::new();
    for (feature_idx, assets) in sponsorships {
        let sponsorship_note = Note::from(
            NetworkSponsorshipNote::builder()
                .sender(sponsor.id())
                .target_account(network_account.id())?
                .feature_note_id(feature_notes[*feature_idx].id())
                .assets(assets.iter().copied())
                .generate_serial_number(&mut rng)
                .build()?,
        );
        builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));
        sponsorship_notes.push(sponsorship_note);
    }

    let mock_chain = builder.build()?;

    Ok(MultiFixture {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    })
}

/// Builds a fee-managed network account, a fee-unaware P2ID feature note targeted at it, and a
/// sponsorship note bound to that feature note carrying `sponsored` of the fee asset.
fn setup(sponsored: u64) -> anyhow::Result<Fixture> {
    let mut f = setup_multi(1, &[(0, vec![fee_asset(sponsored)?])])?;

    Ok(Fixture {
        mock_chain: f.mock_chain,
        network_account: f.network_account,
        feature_note: f.feature_notes.remove(0),
        sponsorship_note: f.sponsorship_notes.remove(0),
    })
}

/// The full single-hop flow.
///
/// The network account consumes the feature note and its sponsorship, keeps the application fee and
/// the note's business asset, and emits one FEE note carrying the protocol fee.
#[tokio::test]
async fn single_hop_settles_the_fee() -> anyhow::Result<()> {
    let f = setup(APP_FEE + PROTOCOL_FEE)?;

    let executed = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .authenticated_input_note(f.feature_note.id())
        .build()?
        .execute()
        .await?;

    // Exactly one output note: the FEE note, carrying the protocol portion, payable to anyone.
    assert_eq!(executed.output_notes().num_notes(), 1, "expected exactly one FEE note");
    assert_note_created!(
        executed,
        note_type: NoteType::Public,
        sender: f.network_account.id(),
        assets: [fee_asset(PROTOCOL_FEE)?],
    );

    let mut network_account = f.network_account;
    network_account.apply_patch(executed.account_patch())?;

    assert_eq!(
        network_account.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        APP_FEE,
        "the account keeps the application fee and forwards the protocol fee",
    );
    assert_eq!(
        network_account.vault().get_balance(business_asset()?.id())?.as_u64(),
        BUSINESS_AMOUNT,
        "the feature note's business asset lands in the account",
    );

    Ok(())
}

/// A sponsor who overpays does not get a refund: the surplus stays with the account.
#[tokio::test]
async fn surplus_sponsorship_stays_with_the_account() -> anyhow::Result<()> {
    const SURPLUS: u64 = 25;
    let f = setup(APP_FEE + PROTOCOL_FEE + SURPLUS)?;

    let executed = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .authenticated_input_note(f.feature_note.id())
        .build()?
        .execute()
        .await?;

    assert_note_created!(executed, assets: [fee_asset(PROTOCOL_FEE)?]);

    let mut network_account = f.network_account;
    network_account.apply_patch(executed.account_patch())?;
    assert_eq!(
        network_account.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        APP_FEE + SURPLUS,
    );

    Ok(())
}

/// A feature note consumed without sponsorship is rejected by the account's auth procedure.
///
/// This is the mirror image of the sponsorship note's own presence check. Consuming a sponsorship
/// without its feature note costs the sponsor, and the note guards that. Consuming a feature note
/// without sponsorship costs the account, and this guards that.
#[tokio::test]
async fn feature_note_without_sponsorship_is_rejected() -> anyhow::Result<()> {
    let f = setup(APP_FEE + PROTOCOL_FEE)?;

    let result = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP);

    Ok(())
}

/// An underfunded sponsorship is rejected.
#[tokio::test]
async fn underfunded_sponsorship_is_rejected() -> anyhow::Result<()> {
    let f = setup(APP_FEE + PROTOCOL_FEE - 1)?;

    let result = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_note.id())
        .authenticated_input_note(f.feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP);

    Ok(())
}

/// Two feature notes settle in one transaction: each needs its own coverage, and the protocol
/// portions are summed into a single FEE note.
#[tokio::test]
async fn two_feature_notes_settle_in_one_tx() -> anyhow::Result<()> {
    let full_fee = vec![fee_asset(APP_FEE + PROTOCOL_FEE)?];
    let f = setup_multi(2, &[(0, full_fee.clone()), (1, full_fee)])?;

    let executed = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_notes[0].id())
        .authenticated_input_note(f.feature_notes[0].id())
        .authenticated_input_note(f.sponsorship_notes[1].id())
        .authenticated_input_note(f.feature_notes[1].id())
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1, "expected a single combined FEE note");
    assert_note_created!(executed, assets: [fee_asset(2 * PROTOCOL_FEE)?]);

    let mut network_account = f.network_account;
    network_account.apply_patch(executed.account_patch())?;
    assert_eq!(
        network_account.vault().get_balance(fee_asset(0)?.id())?.as_u64(),
        2 * APP_FEE,
        "the account keeps one application fee per feature note",
    );
    assert_eq!(
        network_account.vault().get_balance(business_asset()?.id())?.as_u64(),
        2 * BUSINESS_AMOUNT,
    );

    Ok(())
}

/// Coverage is summed across all sponsorships bound to the same feature note, so a second
/// sponsorship is a top-up rather than a conflict.
#[tokio::test]
async fn two_sponsorships_top_up_one_feature_note() -> anyhow::Result<()> {
    // Neither sponsorship covers the fee alone; together they do, exactly.
    let f = setup_multi(1, &[(0, vec![fee_asset(APP_FEE)?]), (0, vec![fee_asset(PROTOCOL_FEE)?])])?;

    let executed = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_notes[0].id())
        .authenticated_input_note(f.sponsorship_notes[1].id())
        .authenticated_input_note(f.feature_notes[0].id())
        .build()?
        .execute()
        .await?;

    assert_note_created!(executed, assets: [fee_asset(PROTOCOL_FEE)?]);

    Ok(())
}

fn wrong_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, amount)?.into())
}

/// The malformed asset lists a hostile sponsor could bind to a real feature note: a wrong asset,
/// and a fully-funded note that nonetheless carries a second asset.
type MalformedAssets = fn() -> anyhow::Result<Vec<Asset>>;

fn wrong_asset_only() -> anyhow::Result<Vec<Asset>> {
    Ok(vec![wrong_asset(APP_FEE + PROTOCOL_FEE)?])
}

fn fee_asset_plus_second_asset() -> anyhow::Result<Vec<Asset>> {
    Ok(vec![fee_asset(APP_FEE + PROTOCOL_FEE)?, wrong_asset(5)?])
}

/// A sponsorship carrying anything other than exactly one asset of the fee asset contributes
/// nothing towards coverage.
#[rstest]
#[case::wrong_asset(wrong_asset_only)]
#[case::two_assets(fee_asset_plus_second_asset)]
#[tokio::test]
async fn malformed_sponsorship_contributes_nothing(
    #[case] malformed: MalformedAssets,
) -> anyhow::Result<()> {
    let f = setup_multi(1, &[(0, malformed()?)])?;

    let result = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_notes[0].id())
        .authenticated_input_note(f.feature_notes[0].id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP);

    Ok(())
}

/// A malformed sponsorship does not block settlement when a valid one covers the note.
///
/// This is the griefing-immunity property: if settlement panicked on the junk note instead of
/// skipping it, anyone could block a feature note by binding a malformed sponsorship to it.
#[rstest]
#[case::wrong_asset(wrong_asset_only)]
#[case::two_assets(fee_asset_plus_second_asset)]
#[tokio::test]
async fn malformed_sponsorship_does_not_block_settlement(
    #[case] malformed: MalformedAssets,
) -> anyhow::Result<()> {
    let f = setup_multi(1, &[(0, malformed()?), (0, vec![fee_asset(APP_FEE + PROTOCOL_FEE)?])])?;

    let executed = f
        .mock_chain
        .build_transaction(f.network_account.id())
        .authenticated_input_note(f.sponsorship_notes[0].id())
        .authenticated_input_note(f.sponsorship_notes[1].id())
        .authenticated_input_note(f.feature_notes[0].id())
        .build()?
        .execute()
        .await?;

    assert_note_created!(executed, assets: [fee_asset(PROTOCOL_FEE)?]);

    Ok(())
}

/// A priced note whose root is not allowlisted is rejected by the auth component before
/// settlement runs: pricing a script does not grant it permission to run.
#[tokio::test]
async fn priced_but_not_allowlisted_note_is_rejected() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();

    let fee_manager = FeeManager::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?)?
        .with_fee(P2idNote::script_root(), FeeScheduleEntry::new(APP_FEE, PROTOCOL_FEE)?);

    // The allowlist holds a placeholder root (plus the auto-inserted sponsorship root): P2ID is
    // priced but not allowlisted.
    let auth = AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::from([
        NoteScriptRoot::from_array([9, 9, 9, 9]),
    ]))?;

    let network_account = AccountBuilder::new([13u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_component(fee_manager)
        .build_existing()?;
    builder.add_account(network_account.clone())?;

    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;
    let feature_note = builder.add_p2id_note(
        sponsor.id(),
        network_account.id(),
        &[business_asset()?],
        NoteType::Public,
    )?;
    let sponsorship_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(network_account.id())?
            .feature_note_id(feature_note.id())
            .asset(fee_asset(APP_FEE + PROTOCOL_FEE)?)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    let mock_chain = builder.build()?;
    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_note.id())
        .authenticated_input_note(feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);

    Ok(())
}

/// A sponsorship this account reclaims in the same transaction does not double as coverage.
///
/// The reclaim path deposits the note's assets into the vault exactly like the sponsorship path
/// does, but a reclaim only happens when the note's bound feature note is absent, and an absent
/// note is never settled: the reclaimed funds match no settled feature note's binding.
#[tokio::test]
async fn reclaimed_sponsorship_does_not_count_as_coverage() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();

    let network_account = add_network_account(&mut builder)?;
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;
    let third_party = builder.add_existing_wallet(Auth::IncrNonce)?;

    let feature_note = builder.add_p2id_note(
        sponsor.id(),
        network_account.id(),
        &[business_asset()?],
        NoteType::Public,
    )?;

    // The network account itself sponsored some other note that never materialized: the binding
    // names a note that is not in this transaction. Fully funded, expired, and reclaimable by the
    // network account as its sender.
    let absent_note_id = NoteId::from_raw(Word::from([11, 12, 13, 14u32]));
    let reclaimable_note = Note::from(
        NetworkSponsorshipNote::builder()
            .sender(network_account.id())
            .target_account(third_party.id())?
            .feature_note_id(absent_note_id)
            .asset(fee_asset(APP_FEE + PROTOCOL_FEE)?)
            .reclaim_height(BlockNumber::from(1u32))
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(reclaimable_note.clone()));

    let mut mock_chain = builder.build()?;
    // Advance past the reclaim height so the reclaim path itself succeeds.
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(reclaimable_note.id())
        .authenticated_input_note(feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP);

    Ok(())
}
