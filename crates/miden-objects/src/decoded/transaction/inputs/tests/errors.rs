use alloc::string::ToString;
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::{StorageSlotNameError, TransactionInputError};
use miden_protocol::note::Note;
use miden_protocol::protocol_config::ProtocolConfig;

use super::common;
use crate::test_utils::error_source;
use crate::{BuildUnchecked, ConversionError, DecodeMessage, proto};

fn transaction_input_error(error: &ConversionError) -> &TransactionInputError {
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<TransactionInputError>() {
            return error;
        }
        source = error.source();
    }
    panic!("transaction input conversion should preserve its domain error")
}

#[test]
fn authenticated_input_note_rejects_a_proof_for_a_different_note() {
    let mut message = common::dummy_transaction_inputs_message();
    common::authenticated_input_note_mut(&mut message)
        .proof
        .as_mut()
        .unwrap()
        .note_id = Some((&Note::mock_noop(common::dummy_word(99)).id()).into());

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert!(error.to_string().starts_with("note ID mismatch:"), "unexpected error: {error}");
}

#[test]
fn input_notes_reject_duplicate_nullifiers_and_preserve_the_domain_source() {
    let mut message = common::dummy_transaction_inputs_message();
    let v1 = common::transaction_inputs_v1_mut(&mut message);
    let duplicate = v1.input_notes.as_ref().unwrap().notes[0].clone();
    v1.input_notes.as_mut().unwrap().notes.push(duplicate);

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert!(
        error.to_string().starts_with("transaction input note with nullifier"),
        "unexpected error: {error}"
    );
    assert_matches!(transaction_input_error(&error), TransactionInputError::DuplicateInputNote(_));
}

#[test]
fn foreign_slot_names_reject_invalid_names_and_preserve_the_domain_source() {
    let mut message = common::dummy_transaction_inputs_message();
    common::transaction_inputs_v1_mut(&mut message).foreign_account_slot_names[0].slot_name =
        "invalid".into();

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<StorageSlotNameError>(&error),
        Some(StorageSlotNameError::TooShort)
    );
}

#[test]
fn foreign_slot_names_reject_id_name_mismatches() {
    let mut message = common::dummy_transaction_inputs_message();
    let v1 = common::transaction_inputs_v1_mut(&mut message);
    v1.foreign_account_slot_names[0].slot_id = v1.foreign_account_slot_names[1].slot_id;

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<crate::decoded::transaction::ForeignAccountSlotNameError>(&error),
        Some(crate::decoded::transaction::ForeignAccountSlotNameError::IdMismatch { .. })
    );
}

#[test]
fn foreign_slot_names_reject_duplicate_ids() {
    let mut message = common::dummy_transaction_inputs_message();
    let v1 = common::transaction_inputs_v1_mut(&mut message);
    let mut duplicate = v1.foreign_account_slot_names[0].clone();
    duplicate.slot_name = v1.foreign_account_slot_names[0].slot_name.clone();
    v1.foreign_account_slot_names.push(duplicate);

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<crate::decoded::transaction::TransactionInputsError>(&error),
        Some(crate::decoded::transaction::TransactionInputsError::DuplicateSlot(_))
    );
}

#[test]
fn transaction_inputs_reject_an_inconsistent_protocol_config() {
    let mut message = common::dummy_transaction_inputs_message();
    common::transaction_inputs_v1_mut(&mut message).protocol_config =
        Some(proto::protocol_config::ProtocolConfig::from(ProtocolConfig::mock()));

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_matches!(
        transaction_input_error(&error),
        TransactionInputError::InconsistentProtocolConfig { .. }
    );
}

#[test]
fn transaction_inputs_reject_an_inconsistent_chain_length() {
    let mut message = common::dummy_transaction_inputs_message();
    let header = common::transaction_inputs_v1_mut(&mut message).block_header.as_mut().unwrap();
    header.block_num = Some(BlockNumber::from(1_u32).into());

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_matches!(
        transaction_input_error(&error),
        TransactionInputError::InconsistentChainLength { .. }
    );
}

#[test]
fn transaction_inputs_reject_an_inconsistent_chain_commitment() {
    let mut message = common::dummy_transaction_inputs_message();
    let header = common::transaction_inputs_v1_mut(&mut message).block_header.as_mut().unwrap();
    header.chain_commitment = Some(common::dummy_word(100).into());

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_matches!(
        transaction_input_error(&error),
        TransactionInputError::InconsistentChainCommitment { .. }
    );
}

#[test]
fn transaction_inputs_reject_an_authenticated_note_from_an_untracked_block() {
    let mut message = common::dummy_transaction_inputs_message();
    common::authenticated_input_note_mut(&mut message)
        .proof
        .as_mut()
        .unwrap()
        .block_num = Some(BlockNumber::from(1_u32).into());

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_matches!(
        transaction_input_error(&error),
        TransactionInputError::InputNoteBlockNotInPartialBlockchain(_)
    );
}

#[test]
fn transaction_inputs_reject_an_invalid_authenticated_note_path() {
    let mut message = common::dummy_transaction_inputs_message();
    let replacement = Note::mock_noop(common::dummy_word(101));
    let authenticated = common::authenticated_input_note_mut(&mut message);
    authenticated.note = Some(replacement.clone().into());
    authenticated.proof.as_mut().unwrap().note_id = Some((&replacement.id()).into());

    let error = message
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_matches!(
        transaction_input_error(&error),
        TransactionInputError::InputNoteNotInBlock(note_id, _) if *note_id == replacement.id()
    );
}
