//! End-to-end tests of the sponsorship fee flow (approach C of discussion #2968).
//!
//! A feature note stays entirely fee-unaware. Its fee travels in a separate sponsorship note that
//! names it by note ID. The network account's auth procedure asserts every feature note it consumed
//! was covered, keeps the application portion, and forwards the protocol portion to the batch
//! builder in a FEE note that anyone may consume.

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::Authority;
use miden_standards::account::fees::{FeeAuth, FeeManager, FeeScheduleEntry};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_FEE_MANAGER_INSUFFICIENT_SPONSORSHIP;
use miden_standards::note::{NetworkSponsorshipNote, P2idNote};
use miden_testing::{Auth, MockChain, assert_note_created, assert_transaction_executor_error};

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

/// Builds a fee-managed network account, a fee-unaware P2ID feature note targeted at it, and a
/// sponsorship note bound to that feature note carrying `sponsored` of the fee asset.
fn setup(sponsored: u64) -> anyhow::Result<Fixture> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();

    let fee_manager = FeeManager::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?)?
        // The feature note is a plain P2ID: it knows nothing about fees.
        .with_fee(P2idNote::script_root(), FeeScheduleEntry::new(APP_FEE, PROTOCOL_FEE)?);

    let network_account = AccountBuilder::new([7u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(FeeAuth)
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
            .asset(fee_asset(sponsored)?)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    let mock_chain = builder.build()?;

    Ok(Fixture {
        mock_chain,
        network_account,
        feature_note,
        sponsorship_note,
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
