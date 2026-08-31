use core::error::Error;

use miden_objects::{ConversionError, proto};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::{StorageSlotNameError, TransactionInputError};
use miden_protocol::note::Note;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::TransactionInputs;

#[path = "support/transaction_inputs.rs"]
mod common;

fn assert_transaction_input_error(
    error: &ConversionError,
    predicate: impl FnOnce(&TransactionInputError) -> bool,
) {
    let source = error.source().unwrap().downcast_ref::<TransactionInputError>().unwrap();
    assert!(predicate(source), "unexpected transaction input error: {source:?}");
}

#[test]
fn transaction_inputs_requires_a_version() {
    let error =
        TransactionInputs::try_from(proto::transaction::TransactionInputs::default()).unwrap_err();

    assert!(error.to_string().ends_with("::version is missing"));
    assert!(error.source().is_some());
}

#[test]
fn transaction_inputs_v1_requires_every_singular_message() {
    type RemoveField = fn(&mut proto::transaction::TransactionInputsV1);

    let fields: [(&str, RemoveField); 7] = [
        ("account", |v1| v1.account = None),
        ("block_header", |v1| v1.block_header = None),
        ("protocol_config", |v1| v1.protocol_config = None),
        ("partial_blockchain", |v1| v1.partial_blockchain = None),
        ("input_notes", |v1| v1.input_notes = None),
        ("tx_args", |v1| v1.tx_args = None),
        ("advice_inputs", |v1| v1.advice_inputs = None),
    ];

    for (field, remove) in fields {
        let mut message = common::transaction_inputs_message();
        remove(common::transaction_inputs_v1(&mut message));
        let error = TransactionInputs::try_from(message).unwrap_err();

        assert!(
            error.to_string().starts_with(&format!("v1.{field}: field ")),
            "unexpected error for {field}: {error}"
        );
        assert!(error.to_string().ends_with(&format!("::{field} is missing")));
        assert!(error.source().is_some());
    }
}

#[test]
fn input_notes_require_their_oneof_and_authenticated_fields() {
    let mut message = common::transaction_inputs_message();
    common::transaction_inputs_v1(&mut message).input_notes.as_mut().unwrap().notes[0].note = None;
    let error = TransactionInputs::try_from(message).unwrap_err();
    assert!(error.to_string().ends_with(
        "input_notes.notes[0]: field miden_objects::proto::transaction::InputNote::note is missing"
    ));

    let mut message = common::transaction_inputs_message();
    common::authenticated_input_note(&mut message).note = None;
    let error = TransactionInputs::try_from(message).unwrap_err();
    assert!(error.to_string().contains("input_notes.notes[0].authenticated"));
    assert!(error.to_string().ends_with("::note is missing"));

    let mut message = common::transaction_inputs_message();
    common::authenticated_input_note(&mut message).proof = None;
    let error = TransactionInputs::try_from(message).unwrap_err();
    assert!(error.to_string().contains("input_notes.notes[0].authenticated"));
    assert!(error.to_string().ends_with("::proof is missing"));
}

#[test]
fn authenticated_input_note_rejects_a_proof_for_a_different_note() {
    let mut message = common::transaction_inputs_message();
    common::authenticated_input_note(&mut message).proof.as_mut().unwrap().note_id =
        Some((&Note::mock_noop(common::word(99)).id()).into());

    let error = TransactionInputs::try_from(message).unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("v1.input_notes.notes[0].authenticated.proof.note_id: note ID mismatch:"),
        "unexpected error: {error}"
    );
    assert!(error.source().is_some());
}

#[test]
fn input_notes_reject_duplicate_nullifiers_and_preserve_the_domain_source() {
    let mut message = common::transaction_inputs_message();
    let v1 = common::transaction_inputs_v1(&mut message);
    let duplicate = v1.input_notes.as_ref().unwrap().notes[0].clone();
    v1.input_notes.as_mut().unwrap().notes.push(duplicate);

    let error = TransactionInputs::try_from(message).unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("v1.input_notes: transaction input note with nullifier"),
        "unexpected error: {error}"
    );
    assert_transaction_input_error(&error, |source| {
        matches!(source, TransactionInputError::DuplicateInputNote(_))
    });
}

#[test]
fn foreign_slot_names_reject_invalid_names_and_preserve_the_domain_source() {
    let mut message = common::transaction_inputs_message();
    common::transaction_inputs_v1(&mut message).foreign_account_slot_names[0].slot_name =
        "invalid".into();

    let error = TransactionInputs::try_from(message).unwrap_err();

    assert!(error.to_string().starts_with("v1.foreign_account_slot_names[0].slot_name: "));
    assert!(error.source().unwrap().downcast_ref::<StorageSlotNameError>().is_some());
}

#[test]
fn foreign_slot_names_reject_id_name_mismatches() {
    let mut message = common::transaction_inputs_message();
    let v1 = common::transaction_inputs_v1(&mut message);
    v1.foreign_account_slot_names[0].slot_id = v1.foreign_account_slot_names[1].slot_id.clone();

    let error = TransactionInputs::try_from(message).unwrap_err();

    assert_eq!(
        error.to_string(),
        "v1.foreign_account_slot_names[0].slot_id: storage slot ID does not match slot name"
    );
    assert!(error.source().is_some());
}

#[test]
fn foreign_slot_names_reject_duplicate_ids() {
    let mut message = common::transaction_inputs_message();
    let v1 = common::transaction_inputs_v1(&mut message);
    let mut duplicate = v1.foreign_account_slot_names[0].clone();
    duplicate.slot_name = v1.foreign_account_slot_names[0].slot_name.clone();
    v1.foreign_account_slot_names.push(duplicate);

    let error = TransactionInputs::try_from(message).unwrap_err();

    assert_eq!(
        error.to_string(),
        "v1.foreign_account_slot_names[2].slot_id: duplicate foreign account storage slot ID"
    );
    assert!(error.source().is_some());
}

#[test]
fn transaction_inputs_reject_an_inconsistent_protocol_config() {
    let mut message = common::transaction_inputs_message();
    common::transaction_inputs_v1(&mut message).protocol_config =
        Some(proto::protocol_config::ProtocolConfig::from(ProtocolConfig::mock()));

    let error = TransactionInputs::try_from(message).unwrap_err();
    assert_transaction_input_error(&error, |source| {
        matches!(source, TransactionInputError::InconsistentProtocolConfig { .. })
    });
}

#[test]
fn transaction_inputs_reject_an_inconsistent_chain_length() {
    let mut message = common::transaction_inputs_message();
    let header = common::transaction_inputs_v1(&mut message).block_header.as_mut().unwrap();
    let Some(proto::blockchain::block_header::Version::V1(header)) = header.version.as_mut() else {
        panic!("block header should encode as v1");
    };
    header.block_num = Some(BlockNumber::from(1_u32).into());

    let error = TransactionInputs::try_from(message).unwrap_err();
    assert_transaction_input_error(&error, |source| {
        matches!(source, TransactionInputError::InconsistentChainLength { .. })
    });
}

#[test]
fn transaction_inputs_reject_an_inconsistent_chain_commitment() {
    let mut message = common::transaction_inputs_message();
    let header = common::transaction_inputs_v1(&mut message).block_header.as_mut().unwrap();
    let Some(proto::blockchain::block_header::Version::V1(header)) = header.version.as_mut() else {
        panic!("block header should encode as v1");
    };
    header.chain_commitment = Some(common::word(100).into());

    let error = TransactionInputs::try_from(message).unwrap_err();
    assert_transaction_input_error(&error, |source| {
        matches!(source, TransactionInputError::InconsistentChainCommitment { .. })
    });
}

#[test]
fn transaction_inputs_reject_an_authenticated_note_from_an_untracked_block() {
    let mut message = common::transaction_inputs_message();
    common::authenticated_input_note(&mut message).proof.as_mut().unwrap().block_num =
        Some(BlockNumber::from(1_u32).into());

    let error = TransactionInputs::try_from(message).unwrap_err();
    assert_transaction_input_error(&error, |source| {
        matches!(source, TransactionInputError::InputNoteBlockNotInPartialBlockchain(_))
    });
}

#[test]
fn transaction_inputs_reject_an_invalid_authenticated_note_path() {
    let mut message = common::transaction_inputs_message();
    let replacement = Note::mock_noop(common::word(101));
    let authenticated = common::authenticated_input_note(&mut message);
    authenticated.note = Some(replacement.clone().into());
    authenticated.proof.as_mut().unwrap().note_id = Some((&replacement.id()).into());

    let error = TransactionInputs::try_from(message).unwrap_err();
    assert_transaction_input_error(
        &error,
        |source| matches!(source, TransactionInputError::InputNoteNotInBlock(note_id, _) if *note_id == replacement.id()),
    );
}
