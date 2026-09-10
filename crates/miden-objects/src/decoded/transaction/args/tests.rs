use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::assembly::mast::MastForestError;
use miden_protocol::utils::serde::DeserializationError;

use crate::decoded::primitives::test_utils::corrupt_node_hash;
use crate::decoded::transaction::test_utils::note_id;
use crate::test_utils::{dummy_word, error_source};
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn transaction_script_defers_entrypoint_validation() {
    let decoded = proto::transaction::TransactionScript {
        entrypoint: 1,
        mast: Some(miden_protocol::MastForest::new().into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.entrypoint, 1);
    assert!(decoded.verify().is_err());
}

#[test]
fn note_argument_verifies_into_tuple() {
    let id = miden_protocol::note::NoteId::from_raw(Word::empty());
    let decoded = proto::transaction::NoteArgument {
        note_id: Some((&id).into()),
        args: Some(Word::from([1_u32, 2, 3, 4]).into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap(), (id, Word::from([1_u32, 2, 3, 4])));
}

#[test]
fn transaction_args_decode_optional_script_without_verifying_it() {
    let input = miden_protocol::transaction::TransactionArgs::from_parts(
        None,
        Word::empty(),
        Default::default(),
        Default::default(),
        Word::empty(),
    );
    let wire = proto::transaction::TransactionArgs::from(&input);
    let decoded = wire.clone().decode_fields().unwrap();
    assert!(decoded.tx_script.is_none());
    assert_eq!(decoded.verify().unwrap(), input);
    let decoded = proto::transaction::TransactionArgs {
        tx_script: Some(proto::transaction::TransactionScript {
            entrypoint: 1,
            mast: Some(miden_protocol::MastForest::new().into()),
        }),
        ..wire
    }
    .decode_fields()
    .unwrap();
    assert!(decoded.tx_script.is_some());
    assert!(decoded.verify().is_err());
}

#[test]
fn note_argument_decoding_normalizes_arbitrary_entry_order() {
    let first = note_id(1);
    let second = note_id(2);
    let args = proto::transaction::TransactionArgs {
        tx_script: None,
        tx_script_args: Some(dummy_word(3).into()),
        note_args: vec![
            proto::transaction::NoteArgument {
                note_id: Some((&second).into()),
                args: Some(dummy_word(4).into()),
            },
            proto::transaction::NoteArgument {
                note_id: Some((&first).into()),
                args: Some(dummy_word(5).into()),
            },
        ],
        advice_inputs: Some(proto::primitives::AdviceInputs {
            advice_stack: Some(proto::primitives::AdviceStack { values: vec![] }),
            advice_map: Some(proto::primitives::AdviceMap { entries: vec![] }),
            merkle_store: Some(proto::primitives::MerkleStore { nodes: vec![] }),
        }),
        auth_args: Some(dummy_word(6).into()),
    }
    .decode_fields()
    .unwrap()
    .verify()
    .unwrap();

    assert_eq!(
        proto::transaction::TransactionArgs::from(&args)
            .note_args
            .iter()
            .map(|entry| entry.note_id.clone().unwrap().decode_fields().unwrap().verify().unwrap())
            .collect::<Vec<_>>(),
        vec![first, second]
    );
}

#[test]
fn transaction_args_reject_duplicate_note_ids() {
    let note = note_id(1);
    let duplicate = proto::transaction::TransactionArgs {
        tx_script: None,
        tx_script_args: Some(dummy_word(2).into()),
        note_args: vec![
            proto::transaction::NoteArgument {
                note_id: Some((&note).into()),
                args: Some(dummy_word(3).into()),
            },
            proto::transaction::NoteArgument {
                note_id: Some((&note).into()),
                args: Some(dummy_word(4).into()),
            },
        ],
        advice_inputs: Some(proto::primitives::AdviceInputs {
            advice_stack: Some(proto::primitives::AdviceStack { values: vec![] }),
            advice_map: Some(proto::primitives::AdviceMap { entries: vec![] }),
            merkle_store: Some(proto::primitives::MerkleStore { nodes: vec![] }),
        }),
        auth_args: Some(dummy_word(5).into()),
    };
    let error = duplicate
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_eq!(error.to_string(), format!("duplicate note argument {note}"));
}

#[test]
fn transaction_script_rejects_invalid_entrypoint_and_malformed_mast() {
    let invalid_entrypoint = proto::transaction::TransactionScript {
        entrypoint: 1,
        mast: Some(miden_protocol::MastForest::new().into()),
    };
    let error = invalid_entrypoint
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_matches!(
        error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<DeserializationError>()),
        Some(DeserializationError::InvalidValue(_))
    );

    let malformed_mast = proto::transaction::TransactionScript {
        entrypoint: 0,
        mast: Some(proto::primitives::MastForest { encoded: vec![0] }),
    };
    let error = malformed_mast.decode_fields().unwrap_err();
    assert!(error.to_string().starts_with("mast.encoded: "), "{error}");
    assert_matches!(
        error.source().and_then(|source| source.downcast_ref::<DeserializationError>()),
        Some(DeserializationError::InvalidValue(message)) if message.contains("budget exhausted")
    );
}

#[test]
fn transaction_script_validates_its_forest() {
    let script = miden_protocol::note::NoteScript::mock();
    let mast = corrupt_node_hash(&script.mast(), script.root().into());
    let wire = proto::transaction::TransactionScript {
        mast: Some(mast),
        entrypoint: script.entrypoint().into(),
    };
    assert!(matches!(
        error_source::<MastForestError>(&wire.decode_fields().unwrap().verify().unwrap_err()),
        Some(MastForestError::HashMismatch { .. })
    ));
}
