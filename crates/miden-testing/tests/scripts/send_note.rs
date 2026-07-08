use core::num::NonZeroU16;
use core::slice;

use miden_processor::ExecutionError;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteRecipient,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::testing::note::DEFAULT_NOTE_SCRIPT;
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_SEND_NOTES_FAUCET_NOTE_REQUIRES_ONE_ASSET;
use miden_standards::note::P2idNote;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_testing::utils::create_p2any_note;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

/// Tests the execution of the generated send_note transaction script in case the sending account
/// has the [`BasicWallet`][wallet] interface.
///
/// This tests consumes a SPAWN note first so that the note_idx in the send_note script is not zero
/// to make sure the note_idx is correctly kept on the stack.
///
/// The test also sends two assets to make sure the generated script deals correctly with multiple
/// assets.
///
/// [wallet]: miden_standards::account::interface::AccountComponentInterface::BasicWallet
#[tokio::test]
async fn test_send_note_script_basic_wallet() -> anyhow::Result<()> {
    let total_asset = FungibleAsset::mock(100);
    let sent_asset0 = NonFungibleAsset::mock(&[4, 5, 6]);

    let sent_asset1 = FungibleAsset::mock(10);
    let sent_asset2 = FungibleAsset::mock(40);

    let mut builder = MockChain::builder();

    let sender_basic_wallet_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [sent_asset0, total_asset],
    )?;
    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let p2any_note = create_p2any_note(
        sender_basic_wallet_account.id(),
        NoteType::Private,
        [sent_asset1],
        &mut rng,
    );
    let spawn_note = builder.add_spawn_note([&p2any_note])?;
    let mock_chain = builder.build()?;

    let attachment_0 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(42)?,
        vec![Word::from([9, 8, 7, 6u32]), Word::from([5, 4, 3, 2u32])],
    )?;
    let attachment_1 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(43)?, Word::from([1, 2, 3, 4u32]));
    let attachment_2 = NoteAttachment::with_words(
        NoteAttachmentScheme::new(44)?,
        vec![Word::from([10, 11, 12, 13u32])],
    )?;
    let attachment_3 =
        NoteAttachment::with_word(NoteAttachmentScheme::new(45)?, Word::from([20, 21, 22, 23u32]));
    let attachments =
        NoteAttachments::new(vec![attachment_0, attachment_1, attachment_2, attachment_3])?;
    assert_eq!(
        attachments.num_attachments() as usize,
        NoteAttachments::MAX_COUNT,
        "test should use max num of attachments"
    );

    let p2id_note: Note = P2idNote::builder()
        .sender(sender_basic_wallet_account.id())
        .target(sender_basic_wallet_account.id())
        .asset(sent_asset0)
        .asset(sent_asset2)
        .attachments(attachments.iter().cloned())
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    let partial_note = PartialNote::from(p2id_note.clone());

    let expiration_delta = NonZeroU16::new(10).expect("10 is non-zero");
    let send_note_transaction_script = SendNotesTransactionScript::with_expiration_delta(
        &sender_basic_wallet_account.code_interface(),
        slice::from_ref(&partial_note),
        expiration_delta,
    )?;

    let executed_transaction = mock_chain
        .build_tx_context(sender_basic_wallet_account.id(), &[spawn_note.id()], &[])
        .expect("failed to build tx context")
        .tx_script(send_note_transaction_script.clone().into())
        .tx_script_args(send_note_transaction_script.tx_script_args())
        .extend_advice_map(send_note_transaction_script.advice_entries().to_vec())
        .extend_expected_output_notes(vec![RawOutputNote::Full(p2id_note.clone())])
        .build()?
        .execute()
        .await?;

    // Assert that the non-fungible asset was removed
    let vault_patch = executed_transaction.account_patch().vault();
    assert_eq!(
        vault_patch.removed_asset_ids().count(),
        1,
        "the non-fungible asset should have been completely removed"
    );
    assert_eq!(
        vault_patch.removed_asset_ids().next().unwrap(),
        &sent_asset0.id(),
        "the non-fungible asset should have been completely removed"
    );

    // Assert that the fungible asset's value was decremented
    assert_eq!(
        vault_patch.updated_assets().count(),
        1,
        "the fungible asset should have been updated"
    );
    // Expected value is total - (sent_asset1 + sent_asset2).
    let expected_removed = sent_asset1.unwrap_fungible().add(sent_asset2.unwrap_fungible())?;
    let expected_asset_value = total_asset.unwrap_fungible().sub(expected_removed)?.into();
    assert_eq!(
        vault_patch.updated_assets().next().unwrap(),
        expected_asset_value,
        "fungible asset should have been decremented"
    );

    assert_eq!(
        executed_transaction.output_notes().get_note(0),
        &RawOutputNote::Partial(p2any_note.into())
    );
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(p2id_note));

    Ok(())
}

/// Tests the execution of the generated send_note transaction script in case the sending account
/// has the [`FungibleFaucet`][faucet] interface.
///
/// [faucet]: miden_standards::account::interface::AccountComponentInterface::FungibleFaucet
#[tokio::test]
async fn test_send_note_script_fungible_faucet() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender_fungible_faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let tag = NoteTag::with_account_target(sender_fungible_faucet_account.id());
    let attachment = NoteAttachment::with_word(NoteAttachmentScheme::new(100)?, Word::empty());
    let metadata = PartialNoteMetadata::new(sender_fungible_faucet_account.id(), NoteType::Public)
        .with_tag(tag);
    let assets = NoteAssets::new(vec![Asset::Fungible(
        FungibleAsset::new(sender_fungible_faucet_account.id(), 10).unwrap(),
    )])?;
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let attachments = NoteAttachments::from(attachment);

    let note = Note::with_attachments(assets.clone(), metadata, recipient, attachments);
    let partial_note: PartialNote = note.clone().into();

    let expiration_delta = NonZeroU16::new(10).expect("10 is non-zero");
    let send_note_transaction_script = SendNotesTransactionScript::with_expiration_delta(
        &sender_fungible_faucet_account.code_interface(),
        slice::from_ref(&partial_note),
        expiration_delta,
    )?;

    let executed_transaction = mock_chain
        .build_tx_context(sender_fungible_faucet_account.id(), &[], &[])
        .expect("failed to build tx context")
        .tx_script(send_note_transaction_script.clone().into())
        .tx_script_args(send_note_transaction_script.tx_script_args())
        .extend_advice_map(send_note_transaction_script.advice_entries().to_vec())
        .extend_expected_output_notes(vec![RawOutputNote::Full(note.clone())])
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note));

    Ok(())
}

/// Tests that the script roots are independent of the concrete notes and expiration delta, and
/// that the wallet and faucet variants have distinct roots.
///
/// The stable roots are what network accounts allowlist, so a change here is a breaking change
/// for every account that has allowlisted them.
#[test]
fn test_send_note_script_roots_are_stable() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let wallet_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [FungibleAsset::mock(100)],
    )?;

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));
    let note_a: Note = P2idNote::builder()
        .sender(wallet_account.id())
        .target(wallet_account.id())
        .asset(FungibleAsset::mock(10))
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    let note_b: Note = P2idNote::builder()
        .sender(wallet_account.id())
        .target(wallet_account.id())
        .asset(FungibleAsset::mock(20))
        .note_type(NoteType::Private)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    let interface = wallet_account.code_interface();
    let script_a =
        SendNotesTransactionScript::new(&interface, slice::from_ref(&note_a.clone().into()))?;
    let script_b = SendNotesTransactionScript::with_expiration_delta(
        &interface,
        &[note_a.into(), note_b.into()],
        NonZeroU16::new(42).expect("42 is non-zero"),
    )?;

    let root_a = TransactionScript::from(script_a).root();
    let root_b = TransactionScript::from(script_b).root();
    assert_eq!(root_a, root_b, "wallet script root should not depend on notes or delta");
    assert_eq!(root_a, SendNotesTransactionScript::wallet_script_root());

    assert_ne!(
        SendNotesTransactionScript::wallet_script_root(),
        SendNotesTransactionScript::faucet_script_root(),
        "wallet and faucet scripts should have distinct roots"
    );

    Ok(())
}

/// Tests that a single wallet transaction can send multiple notes with varying numbers of assets
/// and attachments, exercising the script's variable-size note record walk.
#[tokio::test]
async fn test_send_note_script_multiple_notes_basic_wallet() -> anyhow::Result<()> {
    let total_asset = FungibleAsset::mock(100);

    let mut builder = MockChain::builder();
    let sender_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [total_asset],
    )?;
    let mock_chain = builder.build()?;

    let mut rng = RandomCoin::new(Word::from([1, 2, 3, 4u32]));

    // Note A: one asset, one attachment.
    let attachment =
        NoteAttachment::with_word(NoteAttachmentScheme::new(7)?, Word::from([1, 2, 3, 4u32]));
    let note_a: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(sender_account.id())
        .asset(FungibleAsset::mock(10))
        .attachments([attachment])
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    // Note B: one asset, no attachments.
    let note_b: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(sender_account.id())
        .asset(FungibleAsset::mock(40))
        .note_type(NoteType::Public)
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    // Note C: no assets and no attachments (smallest possible record).
    let metadata = PartialNoteMetadata::new(sender_account.id(), NoteType::Public)
        .with_tag(NoteTag::with_account_target(sender_account.id()));
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let recipient = NoteRecipient::new(rng.draw_word(), note_script, NoteStorage::default());
    let note_c = Note::new(NoteAssets::default(), metadata, recipient);

    let notes: Vec<PartialNote> =
        vec![note_a.clone().into(), note_b.clone().into(), note_c.clone().into()];
    let script = SendNotesTransactionScript::new(&sender_account.code_interface(), &notes)?;

    let executed_transaction = mock_chain
        .build_tx_context(sender_account.id(), &[], &[])?
        .tx_script(script.clone().into())
        .tx_script_args(script.tx_script_args())
        .extend_advice_map(script.advice_entries().to_vec())
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(note_a.clone()),
            RawOutputNote::Full(note_b.clone()),
            RawOutputNote::Full(note_c.clone()),
        ])
        .build()?
        .execute()
        .await?;

    assert_eq!(executed_transaction.output_notes().num_notes(), 3);
    assert_eq!(executed_transaction.output_notes().get_note(0), &RawOutputNote::Full(note_a));
    assert_eq!(executed_transaction.output_notes().get_note(1), &RawOutputNote::Full(note_b));
    assert_eq!(executed_transaction.output_notes().get_note(2), &RawOutputNote::Full(note_c));

    Ok(())
}

/// Tests that a payload that does not match the commitment in the transaction script argument
/// is rejected by the script's advice validation.
#[tokio::test]
async fn test_send_note_script_tampered_payload_fails() -> anyhow::Result<()> {
    let (mock_chain, sender_account, note) = wallet_chain_with_note()?;

    let script =
        SendNotesTransactionScript::new(&sender_account.code_interface(), &[note.clone().into()])?;

    // Tamper with the payload (flip the expiration delta element) while keeping the advice map
    // key and the transaction script argument at the original commitment.
    let mut advice_entries = script.advice_entries().to_vec();
    let payload = &mut advice_entries[0].1;
    payload[1] += Felt::from(1u32);

    let result = mock_chain
        .build_tx_context(sender_account.id(), &[], &[])?
        .tx_script(script.clone().into())
        .tx_script_args(script.tx_script_args())
        .extend_advice_map(advice_entries)
        .build()?
        .execute()
        .await;

    // The commitment check in `pipe_preimage_to_memory` must reject the mismatch.
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::OperationError {
            err: miden_processor::operation::OperationError::FailedAssertion { .. },
            ..
        }
    );

    Ok(())
}

/// Tests that executing the script without providing the payload in the advice map fails when
/// the script looks up the payload commitment.
#[tokio::test]
async fn test_send_note_script_missing_advice_entries_fails() -> anyhow::Result<()> {
    let (mock_chain, sender_account, note) = wallet_chain_with_note()?;

    let script =
        SendNotesTransactionScript::new(&sender_account.code_interface(), &[note.clone().into()])?;

    // Pass the script and its args, but omit the advice entries.
    let result = mock_chain
        .build_tx_context(sender_account.id(), &[], &[])?
        .tx_script(script.clone().into())
        .tx_script_args(script.tx_script_args())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, matches ExecutionError::AdviceError { .. });

    Ok(())
}

/// Tests that the faucet script's defense-in-depth assertion rejects a handcrafted payload whose
/// note record claims more than one asset, bypassing the Rust-side validation.
#[tokio::test]
async fn test_send_note_script_faucet_rejects_multi_asset_payload() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet_account = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "POL",
        200,
        None,
    )?;
    let mock_chain = builder.build()?;

    let metadata = PartialNoteMetadata::new(faucet_account.id(), NoteType::Public)
        .with_tag(NoteTag::with_account_target(faucet_account.id()));
    let assets =
        NoteAssets::new(vec![Asset::Fungible(FungibleAsset::new(faucet_account.id(), 10)?)])?;
    let note_script = CodeBuilder::default().compile_note_script(DEFAULT_NOTE_SCRIPT).unwrap();
    let serial_num = RandomCoin::new(Word::from([1, 2, 3, 4u32])).draw_word();
    let recipient = NoteRecipient::new(serial_num, note_script, NoteStorage::default());
    let note = Note::new(assets, metadata, recipient);

    let script = SendNotesTransactionScript::new(&faucet_account.code_interface(), &[note.into()])?;

    // Handcraft a payload whose note record claims two assets (element 6 of the first note
    // record, i.e. element 10 of the payload) and recompute the commitment so the payload
    // passes the advice validation and reaches the script's own assertion.
    let (_, mut payload) = script.advice_entries()[0].clone();
    payload[10] = Felt::from(2u32);
    let tampered_args = Hasher::hash_elements(&payload);

    let result = mock_chain
        .build_tx_context(faucet_account.id(), &[], &[])?
        .tx_script(script.clone().into())
        .tx_script_args(tampered_args)
        .extend_advice_map([(tampered_args, payload)])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SEND_NOTES_FAUCET_NOTE_REQUIRES_ONE_ASSET);

    Ok(())
}

/// Builds a mock chain with a basic wallet account holding a fungible asset and a P2ID note
/// sending part of that asset back to the account.
fn wallet_chain_with_note() -> anyhow::Result<(MockChain, miden_protocol::account::Account, Note)> {
    let mut builder = MockChain::builder();
    let sender_account = builder.add_existing_wallet_with_assets(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        [FungibleAsset::mock(100)],
    )?;
    let mock_chain = builder.build()?;

    let note: Note = P2idNote::builder()
        .sender(sender_account.id())
        .target(sender_account.id())
        .asset(FungibleAsset::mock(10))
        .note_type(NoteType::Public)
        .generate_serial_number(&mut RandomCoin::new(Word::from([1, 2, 3, 4u32])))
        .build()?
        .into();

    Ok((mock_chain, sender_account, note))
}
