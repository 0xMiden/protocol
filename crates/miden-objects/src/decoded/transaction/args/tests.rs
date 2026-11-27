use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::error::Error;

use assert_matches::assert_matches;
use miden_protocol::crypto::ecdh::ecgfp5::SecretKey;
use miden_protocol::errors::TransactionArgsError;
use miden_protocol::utils::serde::{DeserializationError, Serializable};
use miden_protocol::{MAX_IES_PREPARED_KEYS_PER_TX, Word};

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
        Default::default(),
        Default::default(),
        Word::empty(),
        None,
        None,
    );
    let wire = proto::transaction::TransactionArgs::from(&input);
    let decoded = wire.clone().decode_fields().unwrap();
    assert!(decoded.tx_script.as_ref().is_none());
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
    assert!(decoded.tx_script.as_ref().is_some());
    let error = decoded.verify().unwrap_err();
    assert!(error.to_string().starts_with("tx_script:"), "{error}");
    assert!(matches!(
        error_source::<DeserializationError>(&error),
        Some(DeserializationError::InvalidValue(_))
    ));
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
        account_code_upgrade: None,
        output_note_recipients: vec![],
        signatures: vec![],
        ies_seal_seed: None,
        ies_public_keys: vec![],
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
        account_code_upgrade: None,
        output_note_recipients: vec![],
        signatures: vec![],
        ies_seal_seed: None,
        ies_public_keys: vec![],
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

/// Decoding counts a repeated IES public key once and rejects more than
/// [`MAX_IES_PREPARED_KEYS_PER_TX`] distinct keys, before any prepared tables are built.
#[rstest::rstest]
#[case::at_cap((1..=MAX_IES_PREPARED_KEYS_PER_TX as u8).collect(), true)]
#[case::repeated_key_counts_once(
    (1..=MAX_IES_PREPARED_KEYS_PER_TX as u8).chain([1]).collect(),
    true
)]
#[case::above_cap((1..=MAX_IES_PREPARED_KEYS_PER_TX as u8 + 1).collect(), false)]
fn transaction_args_cap_ies_public_keys(#[case] key_seeds: Vec<u8>, #[case] is_accepted: bool) {
    let ies_public_keys = key_seeds
        .iter()
        .map(|&seed| proto::transaction::IesPublicKey {
            key: Serializable::to_bytes(&SecretKey::from_bytes(&[seed; 40]).unwrap().public_key()),
        })
        .collect();
    let args = proto::transaction::TransactionArgs {
        tx_script: None,
        tx_script_args: Some(dummy_word(1).into()),
        note_args: vec![],
        advice_inputs: Some(proto::primitives::AdviceInputs {
            advice_stack: Some(proto::primitives::AdviceStack { values: vec![] }),
            advice_map: Some(proto::primitives::AdviceMap { entries: vec![] }),
            merkle_store: Some(proto::primitives::MerkleStore { nodes: vec![] }),
        }),
        auth_args: Some(dummy_word(2).into()),
        account_code_upgrade: None,
        output_note_recipients: vec![],
        signatures: vec![],
        ies_seal_seed: None,
        ies_public_keys,
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new);

    if is_accepted {
        let args = args.unwrap();
        assert_eq!(args.ies_public_keys().count(), MAX_IES_PREPARED_KEYS_PER_TX);
    } else {
        assert_eq!(
            args.unwrap_err().to_string(),
            TransactionArgsError::TooManyIesPublicKeys.to_string()
        );
    }
}
