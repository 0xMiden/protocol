use anyhow::Context;
use miden_protocol::account::{Account, AccountId, AccountStorageMode, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteAssets, NoteDetails, NoteMetadata, NoteTag, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    AccountIdBuilder,
};
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_testing::{Auth, MockChain};

use crate::prove_and_verify_transaction;

/// Creates a SWAP note from the transaction script and proves and verifies the transaction.
#[tokio::test]
pub async fn prove_send_swap_note() -> anyhow::Result<()> {
    let payback_note_type = NoteType::Private;
    let SwapTestSetup {
        mock_chain,
        mut sender_account,
        offered_asset,
        swap_note,
        ..
    } = setup_swap_test(payback_note_type)?;

    // CREATE SWAP NOTE TX
    // --------------------------------------------------------------------------------------------

    let tx_script_src = &format!(
        "
        use miden::protocol::output_note
        begin
            push.{recipient}
            push.{note_type}
            push.{tag}
            exec.output_note::create

            push.{asset}
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw dropw dropw dropw
        end
        ",
        recipient = swap_note.recipient().digest(),
        note_type = NoteType::Public as u8,
        tag = Felt::from(swap_note.metadata().tag()),
        asset = Word::from(offered_asset),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_src)?;

    let create_swap_note_tx = mock_chain
        .build_tx_context(sender_account.id(), &[], &[])
        .context("failed to build tx context")?
        .tx_script(tx_script)
        .extend_expected_output_notes(vec![OutputNote::Full(swap_note.clone())])
        .build()?
        .execute()
        .await?;

    sender_account
        .apply_delta(create_swap_note_tx.account_delta())
        .context("failed to apply delta")?;

    assert!(
        create_swap_note_tx
            .output_notes()
            .iter()
            .any(|n| n.commitment() == swap_note.commitment())
    );
    assert_eq!(
        sender_account.vault().assets().count(),
        0,
        "offered asset should no longer be present in vault"
    );

    let swap_output_note = create_swap_note_tx.output_notes().iter().next().unwrap();
    assert_eq!(swap_output_note.assets().unwrap().iter().next().unwrap(), &offered_asset);
    assert!(prove_and_verify_transaction(create_swap_note_tx).is_ok());

    Ok(())
}

/// Creates a SWAP note in the mock chain with a private payback note and consumes it, creating the
/// payback note. The payback note is consumed by the original sender of the SWAP note.
///
/// Both transactions are proven and verified.
#[tokio::test]
async fn consume_swap_note_private_payback_note() -> anyhow::Result<()> {
    let payback_note_type = NoteType::Private;
    let SwapTestSetup {
        mock_chain,
        mut sender_account,
        mut target_account,
        offered_asset,
        requested_asset,
        swap_note,
        payback_note,
    } = setup_swap_test(payback_note_type)?;

    // CONSUME CREATED NOTE
    // --------------------------------------------------------------------------------------------

    let consume_swap_note_tx = mock_chain
        .build_tx_context(target_account.id(), &[swap_note.id()], &[])
        .context("failed to build tx context")?
        .build()?
        .execute()
        .await?;

    target_account
        .apply_delta(consume_swap_note_tx.account_delta())
        .context("failed to apply delta to target account")?;

    let output_payback_note = consume_swap_note_tx.output_notes().iter().next().unwrap().clone();
    assert!(output_payback_note.id() == payback_note.id());
    assert_eq!(output_payback_note.assets().unwrap().iter().next().unwrap(), &requested_asset);

    assert!(target_account.vault().assets().count() == 1);
    assert!(target_account.vault().assets().any(|asset| asset == offered_asset));

    // CONSUME PAYBACK P2ID NOTE
    // --------------------------------------------------------------------------------------------

    let full_payback_note = Note::new(
        payback_note.assets().clone(),
        output_payback_note.metadata().clone(),
        payback_note.recipient().clone(),
    );

    let consume_payback_tx = mock_chain
        .build_tx_context(sender_account.id(), &[], &[full_payback_note])
        .context("failed to build tx context")?
        .build()?
        .execute()
        .await?;

    sender_account
        .apply_delta(consume_payback_tx.account_delta())
        .context("failed to apply delta to sender account")?;

    assert!(sender_account.vault().assets().any(|asset| asset == requested_asset));

    prove_and_verify_transaction(consume_swap_note_tx)
        .context("failed to prove/verify consume_swap_note_tx")?;

    prove_and_verify_transaction(consume_payback_tx)
        .context("failed to prove/verify consume_payback_tx")?;

    Ok(())
}

// Creates a swap note with a public payback note, then consumes it to complete the swap
// The target account receives the offered asset and creates a public payback note for the sender
#[tokio::test]
async fn consume_swap_note_public_payback_note() -> anyhow::Result<()> {
    let payback_note_type = NoteType::Public;
    let SwapTestSetup {
        mock_chain,
        mut sender_account,
        mut target_account,
        offered_asset,
        requested_asset,
        swap_note,
        payback_note,
    } = setup_swap_test(payback_note_type)?;

    // CONSUME CREATED NOTE
    // --------------------------------------------------------------------------------------------

    // When consuming a SWAP note with a public payback note output
    // it is necessary to add the details of the public note to the advice provider
    // via `.extend_expected_output_notes()`
    let payback_p2id_note = create_p2id_note_exact(
        target_account.id(),
        sender_account.id(),
        vec![requested_asset],
        payback_note_type,
        payback_note.serial_num(),
    )
    .unwrap();

    let consume_swap_note_tx = mock_chain
        .build_tx_context(target_account.id(), &[swap_note.id()], &[])
        .context("failed to build tx context")?
        .extend_expected_output_notes(vec![OutputNote::Full(payback_p2id_note)])
        .build()?
        .execute()
        .await?;

    target_account.apply_delta(consume_swap_note_tx.account_delta())?;

    let output_payback_note = consume_swap_note_tx.output_notes().iter().next().unwrap().clone();
    assert!(output_payback_note.id() == payback_note.id());
    assert_eq!(output_payback_note.assets().unwrap().iter().next().unwrap(), &requested_asset);

    assert!(target_account.vault().assets().count() == 1);
    assert!(target_account.vault().assets().any(|asset| asset == offered_asset));

    // CONSUME PAYBACK P2ID NOTE
    // --------------------------------------------------------------------------------------------

    let full_payback_note = Note::new(
        payback_note.assets().clone(),
        output_payback_note.metadata().clone(),
        payback_note.recipient().clone(),
    );

    let consume_payback_tx = mock_chain
        .build_tx_context(sender_account.id(), &[], &[full_payback_note])
        .context("failed to build tx context")?
        .build()?
        .execute()
        .await?;

    sender_account.apply_delta(consume_payback_tx.account_delta())?;

    assert!(sender_account.vault().assets().any(|asset| asset == requested_asset));
    Ok(())
}

/// Tests that a SWAP note offering asset A and requesting asset B can be matched against a SWAP
/// note offering asset B and requesting asset A.
#[tokio::test]
async fn settle_coincidence_of_wants() -> anyhow::Result<()> {
    // Create two different assets for the swap
    let faucet0 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?;
    let faucet1 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?;
    let asset_a = FungibleAsset::new(faucet0, 10_777)?.into();
    let asset_b = FungibleAsset::new(faucet1, 10)?.into();

    let mut builder = MockChain::builder();

    // CREATE ACCOUNT 1: Has asset A, wants asset B
    // --------------------------------------------------------------------------------------------
    let account_1 = builder.add_existing_wallet_with_assets(Auth::BasicAuth, vec![asset_a])?;

    let payback_note_type = NoteType::Private;
    let (swap_note_1, payback_note_1) =
        builder.add_swap_note(account_1.id(), asset_a, asset_b, payback_note_type)?;

    // CREATE ACCOUNT 2: Has asset B, wants asset A
    // --------------------------------------------------------------------------------------------
    let account_2 = builder.add_existing_wallet_with_assets(Auth::BasicAuth, vec![asset_b])?;

    let (swap_note_2, payback_note_2) =
        builder.add_swap_note(account_2.id(), asset_b, asset_a, payback_note_type)?;

    // MATCHER ACCOUNT: Has both assets and will fulfill both swaps
    // --------------------------------------------------------------------------------------------

    // TODO: matcher account should be able to fill both SWAP notes without holding assets A & B
    let matcher_account =
        builder.add_existing_wallet_with_assets(Auth::BasicAuth, vec![asset_a, asset_b])?;
    // Initial matching account balance should have two assets.
    assert_eq!(matcher_account.vault().assets().count(), 2);

    // EXECUTE SINGLE TRANSACTION TO CONSUME BOTH SWAP NOTES
    // --------------------------------------------------------------------------------------------
    let mock_chain = builder.build()?;
    let settle_tx = mock_chain
        .build_tx_context(matcher_account.id(), &[swap_note_1.id(), swap_note_2.id()], &[])
        .context("failed to build tx context")?
        .build()?
        .execute()
        .await?;

    // VERIFY PAYBACK NOTES WERE CREATED CORRECTLY
    // --------------------------------------------------------------------------------------------
    let output_notes: Vec<_> = settle_tx.output_notes().iter().collect();
    assert_eq!(output_notes.len(), 2);

    // Find payback notes by matching their IDs
    let output_payback_1 = output_notes
        .iter()
        .find(|note| note.id() == payback_note_1.id())
        .expect("Payback note 1 not found");
    let output_payback_2 = output_notes
        .iter()
        .find(|note| note.id() == payback_note_2.id())
        .expect("Payback note 2 not found");

    // Verify payback note 1 contains exactly the initially requested asset B for account 1
    assert_eq!(output_payback_1.assets().unwrap().iter().next().unwrap(), &asset_b);

    // Verify payback note 2 contains exactly the initially requested asset A for account 2
    assert_eq!(output_payback_2.assets().unwrap().iter().next().unwrap(), &asset_a);

    Ok(())
}

struct SwapTestSetup {
    mock_chain: MockChain,
    sender_account: Account,
    target_account: Account,
    offered_asset: Asset,
    requested_asset: Asset,
    swap_note: Note,
    payback_note: NoteDetails,
}

fn setup_swap_test(payback_note_type: NoteType) -> anyhow::Result<SwapTestSetup> {
    let faucet_id = AccountIdBuilder::new()
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Private)
        .build_with_seed([5; 32]);

    let offered_asset = FungibleAsset::new(faucet_id, 2000)?.into();
    let requested_asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let mut builder = MockChain::builder();
    let sender_account =
        builder.add_existing_wallet_with_assets(Auth::BasicAuth, vec![offered_asset])?;
    let target_account =
        builder.add_existing_wallet_with_assets(Auth::BasicAuth, vec![requested_asset])?;

    let (swap_note, payback_note) = builder
        .add_swap_note(sender_account.id(), offered_asset, requested_asset, payback_note_type)
        .unwrap();

    builder.add_output_note(OutputNote::Full(swap_note.clone()));
    let mock_chain = builder.build()?;

    Ok(SwapTestSetup {
        mock_chain,
        sender_account,
        target_account,
        offered_asset,
        requested_asset,
        swap_note,
        payback_note,
    })
}

/// Generates a P2ID note - Pay-to-ID note with an exact serial number
pub fn create_p2id_note_exact(
    sender: AccountId,
    target: AccountId,
    assets: Vec<Asset>,
    note_type: NoteType,
    serial_num: Word,
) -> Result<Note, NoteError> {
    let recipient = P2idNote::build_recipient(target, serial_num)?;

    let tag = NoteTag::with_account_target(target);

    let metadata = NoteMetadata::new(sender, note_type, tag);
    let vault = NoteAssets::new(assets)?;

    Ok(Note::new(vault, metadata, recipient))
}
