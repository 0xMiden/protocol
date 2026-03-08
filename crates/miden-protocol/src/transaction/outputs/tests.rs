use assert_matches::assert_matches;

use super::{PublicOutputNote, RawOutputNote, RawOutputNotes};
use crate::account::AccountId;
use crate::assembly::Assembler;
use crate::asset::FungibleAsset;
use crate::constants::NOTE_MAX_SIZE;
use crate::errors::{OutputNoteError, TransactionOutputError};
use crate::note::{
    Note,
    NoteAssets,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use crate::testing::account_id::{
    ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_SENDER,
};
use crate::utils::serde::Serializable;
use crate::{Felt, Word};

#[test]
fn test_duplicate_output_notes() -> anyhow::Result<()> {
    let mock_note = Note::mock_noop(Word::empty());
    let mock_note_id = mock_note.id();
    let mock_note_clone = mock_note.clone();

    let error = RawOutputNotes::new(vec![
        RawOutputNote::Full(mock_note),
        RawOutputNote::Full(mock_note_clone),
    ])
    .expect_err("input notes creation should fail");

    assert_matches!(error, TransactionOutputError::DuplicateOutputNote(note_id) if note_id == mock_note_id);

    Ok(())
}

#[test]
fn output_note_size_hint_matches_serialized_length() -> anyhow::Result<()> {
    let sender_id = ACCOUNT_ID_SENDER.try_into().unwrap();

    // Build a note with at least two assets.
    let faucet_id_1 = AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET).unwrap();
    let faucet_id_2 = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    let asset_1 = FungibleAsset::new(faucet_id_1, 100)?.into();
    let asset_2 = FungibleAsset::new(faucet_id_2, 200)?.into();

    let assets = NoteAssets::new(vec![asset_1, asset_2])?;

    // Build metadata similarly to how mock notes are constructed.
    let metadata = NoteMetadata::new(sender_id, NoteType::Private)
        .with_tag(NoteTag::with_account_target(sender_id));

    // Build storage with at least two values.
    let storage = NoteStorage::new(vec![Felt::new(1), Felt::new(2)])?;

    let serial_num = Word::empty();
    let script = NoteScript::mock();
    let recipient = NoteRecipient::new(serial_num, script, storage);

    let note = Note::new(assets, metadata, recipient);
    let output_note = RawOutputNote::Full(note);

    let bytes = output_note.to_bytes();

    assert_eq!(bytes.len(), output_note.get_size_hint());

    Ok(())
}

#[test]
fn oversized_public_note_triggers_size_limit_error() -> anyhow::Result<()> {
    // Construct a public note whose serialized size exceeds NOTE_MAX_SIZE by creating
    // a very large note script so that the script's serialized MAST alone is larger
    // than the configured limit.

    let sender_id = ACCOUNT_ID_SENDER.try_into().unwrap();

    // Build a large MASM program with many `nop` instructions.
    let mut src = alloc::string::String::from("begin\n");
    // The exact threshold is not critical as long as we clearly exceed NOTE_MAX_SIZE.
    // After strip_decorators(), the size is reduced, so we need more nops.
    for _ in 0..50000 {
        src.push_str("    nop\n");
    }
    src.push_str("end\n");

    let assembler = Assembler::default();
    let program = assembler.assemble_program(&src).unwrap();
    let script = NoteScript::new(program);

    let serial_num = Word::empty();
    let storage = NoteStorage::new(alloc::vec::Vec::new())?;

    // Create a public note (NoteType::Public is required for PublicOutputNote)
    let faucet_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET).unwrap();
    let asset = FungibleAsset::new(faucet_id, 100)?.into();
    let assets = NoteAssets::new(vec![asset])?;

    let metadata = NoteMetadata::new(sender_id, NoteType::Public)
        .with_tag(NoteTag::with_account_target(sender_id));

    let recipient = NoteRecipient::new(serial_num, script, storage);
    let oversized_note = Note::new(assets, metadata, recipient);

    // Sanity-check that our constructed note is indeed larger than the configured
    // maximum.
    let computed_note_size = oversized_note.get_size_hint();
    assert!(computed_note_size > NOTE_MAX_SIZE as usize);

    // Creating a PublicOutputNote should fail with size limit error
    let result = PublicOutputNote::new(oversized_note.clone());

    assert_matches!(
        result,
        Err(OutputNoteError::NoteSizeLimitExceeded { note_id: _, note_size })
            if note_size > NOTE_MAX_SIZE as usize
    );

    // to_output_note() should also fail
    let output_note = RawOutputNote::Full(oversized_note);
    let result = output_note.to_output_note();

    assert_matches!(
        result,
        Err(OutputNoteError::NoteSizeLimitExceeded { note_id: _, note_size })
            if note_size > NOTE_MAX_SIZE as usize
    );

    Ok(())
}
