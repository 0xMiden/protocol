use core::error::Error;
use std::collections::BTreeMap;

use assert_matches::assert_matches;
use miden_objects::proto;
use miden_protocol::crypto::merkle::InnerNodeInfo;
use miden_protocol::crypto::merkle::store::MerkleStore;
use miden_protocol::note::{Note, NoteId};
use miden_protocol::transaction::TransactionArgs;
use miden_protocol::utils::serde::DeserializationError;
use miden_protocol::vm::{AdviceInputs, AdviceMap};
use miden_protocol::{Felt, Word};

fn dummy_word(value: u32) -> Word {
    Word::from([value, 0, 0, 0])
}

fn note_id(value: u32) -> NoteId {
    Note::mock_noop(dummy_word(value)).id()
}

#[test]
fn advice_inputs_roundtrip_preserves_stack_order_and_normalizes_map_order() {
    let mut store = MerkleStore::new();
    store.extend([InnerNodeInfo {
        value: dummy_word(9),
        left: dummy_word(10),
        right: dummy_word(11),
    }]);
    let advice_inputs = AdviceInputs::default()
        .with_advice_stack({
            let mut stack = AdviceInputs::default().advice_stack();
            stack.append_elements([Felt::from(1_u32), Felt::from(2_u32)]);
            stack
        })
        .with_map([
            (dummy_word(7), vec![Felt::from(3_u32)]),
            (dummy_word(5), vec![Felt::from(4_u32)]),
        ])
        .with_merkle_store(store);

    let message = proto::primitives::AdviceInputs::from(&advice_inputs);

    assert_eq!(
        message.advice_stack.as_ref().unwrap().values,
        vec![Felt::from(1_u32).into(), Felt::from(2_u32).into()]
    );
    assert_eq!(
        message
            .advice_map
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .map(|entry| Word::try_from(entry.key.clone().unwrap()).unwrap())
            .collect::<Vec<_>>(),
        vec![dummy_word(5), dummy_word(7)]
    );
    assert_eq!(AdviceInputs::try_from(message).unwrap(), advice_inputs);
}

#[test]
fn advice_map_decoding_normalizes_arbitrary_entry_order() {
    let map = AdviceMap::try_from(proto::primitives::AdviceMap {
        entries: vec![
            proto::primitives::AdviceMapEntry {
                key: Some(dummy_word(7).into()),
                values: vec![Felt::from(3_u32).into()],
            },
            proto::primitives::AdviceMapEntry {
                key: Some(dummy_word(5).into()),
                values: vec![Felt::from(4_u32).into()],
            },
        ],
    })
    .unwrap();

    assert_eq!(
        proto::primitives::AdviceMap::from(&map)
            .entries
            .iter()
            .map(|entry| Word::try_from(entry.key.clone().unwrap()).unwrap())
            .collect::<Vec<_>>(),
        vec![dummy_word(5), dummy_word(7)]
    );
}

#[test]
fn merkle_store_omits_identical_defaults_and_retains_default_parent_overrides() {
    let default_store = MerkleStore::new();
    let default_node = default_store.inner_nodes().next().unwrap();
    let mut store = MerkleStore::new();
    let override_node = InnerNodeInfo {
        value: default_node.value,
        left: dummy_word(12),
        right: default_node.right,
    };
    let custom_node = InnerNodeInfo {
        value: dummy_word(9),
        left: dummy_word(10),
        right: dummy_word(11),
    };
    store.extend([override_node.clone(), custom_node.clone()]);

    let default_message = proto::primitives::MerkleStore::from(&default_store);
    let override_message = proto::primitives::MerkleStore::from(&store);

    assert!(default_message.nodes.is_empty());
    assert_eq!(override_message.nodes.len(), 2);
    assert!(
        Word::try_from(override_message.nodes[0].value.clone().unwrap()).unwrap()
            < Word::try_from(override_message.nodes[1].value.clone().unwrap()).unwrap()
    );
    assert_eq!(MerkleStore::try_from(default_message).unwrap(), default_store);
    assert_eq!(MerkleStore::try_from(override_message).unwrap(), store);
}

#[test]
fn transaction_args_roundtrip_normalizes_note_args_order() {
    let first = note_id(1);
    let second = note_id(2);
    let args = TransactionArgs::from_parts(
        None,
        dummy_word(3),
        BTreeMap::from([(second, dummy_word(4)), (first, dummy_word(5))]),
        AdviceInputs::default().with_map([(dummy_word(6), vec![Felt::from(7_u32)])]),
        dummy_word(8),
    );

    let message = proto::transaction::TransactionArgs::from(&args);

    assert_eq!(
        message
            .note_args
            .iter()
            .map(|entry| NoteId::from_raw(Word::try_from(entry.note_id.clone().unwrap()).unwrap()))
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(TransactionArgs::try_from(message).unwrap(), args);
}

#[test]
fn note_argument_decoding_normalizes_arbitrary_entry_order() {
    let first = note_id(1);
    let second = note_id(2);
    let args = TransactionArgs::try_from(proto::transaction::TransactionArgs {
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
    })
    .unwrap();

    assert_eq!(
        proto::transaction::TransactionArgs::from(&args)
            .note_args
            .iter()
            .map(|entry| NoteId::from_raw(Word::try_from(entry.note_id.clone().unwrap()).unwrap()))
            .collect::<Vec<_>>(),
        vec![first, second]
    );
}

#[test]
fn advice_inputs_require_nested_messages_and_reject_duplicate_map_keys() {
    let missing_stack = proto::primitives::AdviceInputs {
        advice_stack: None,
        advice_map: Some(proto::primitives::AdviceMap { entries: vec![] }),
        merkle_store: Some(proto::primitives::MerkleStore { nodes: vec![] }),
    };
    let error = AdviceInputs::try_from(missing_stack).unwrap_err();
    assert!(error.to_string().ends_with("::advice_stack is missing"));

    let duplicate = proto::primitives::AdviceMap {
        entries: vec![
            proto::primitives::AdviceMapEntry {
                key: Some(dummy_word(1).into()),
                values: vec![Felt::from(2_u32).into()],
            },
            proto::primitives::AdviceMapEntry {
                key: Some(dummy_word(1).into()),
                values: vec![Felt::from(3_u32).into()],
            },
        ],
    };
    let error = AdviceMap::try_from(duplicate).unwrap_err();
    assert_eq!(error.to_string(), "entries[1].key: duplicate advice map key");
}

#[test]
fn advice_stack_rejects_invalid_felts() {
    let error = miden_protocol::vm::AdviceStack::try_from(proto::primitives::AdviceStack {
        values: vec![proto::primitives::Felt { value: Felt::ORDER }],
    })
    .unwrap_err();

    assert_matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<<Felt as TryFrom<u64>>::Error>()),
        Some(source) if source.as_u64() == Felt::ORDER
    );
}

#[test]
fn merkle_store_rejects_duplicate_parents_and_preserves_invalid_word_source() {
    let node = proto::primitives::MerkleStoreNode {
        value: Some(dummy_word(1).into()),
        left: Some(dummy_word(2).into()),
        right: Some(dummy_word(3).into()),
    };
    let duplicate = proto::primitives::MerkleStore { nodes: vec![node.clone(), node] };
    let error = MerkleStore::try_from(duplicate).unwrap_err();
    assert_eq!(error.to_string(), "nodes[1].value: duplicate Merkle store parent");

    let invalid = proto::primitives::MerkleStore {
        nodes: vec![proto::primitives::MerkleStoreNode {
            value: Some(proto::primitives::Word { encoded: vec![0; 31] }),
            left: Some(dummy_word(2).into()),
            right: Some(dummy_word(3).into()),
        }],
    };
    let error = MerkleStore::try_from(invalid).unwrap_err();
    assert!(error.to_string().starts_with("nodes[0].value.word.encoded: "), "{error}");
    assert!(error.source().is_some());
}

#[test]
fn transaction_args_require_nested_messages_and_reject_duplicate_note_ids() {
    let missing = proto::transaction::TransactionArgs {
        tx_script: None,
        tx_script_args: None,
        note_args: vec![],
        advice_inputs: Some(proto::primitives::AdviceInputs {
            advice_stack: Some(proto::primitives::AdviceStack { values: vec![] }),
            advice_map: Some(proto::primitives::AdviceMap { entries: vec![] }),
            merkle_store: Some(proto::primitives::MerkleStore { nodes: vec![] }),
        }),
        auth_args: Some(dummy_word(1).into()),
    };
    let error = TransactionArgs::try_from(missing).unwrap_err();
    assert!(error.to_string().ends_with("::tx_script_args is missing"));

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
    let error = TransactionArgs::try_from(duplicate).unwrap_err();
    assert_eq!(error.to_string(), "note_args[1].note_id: duplicate note argument");
}

#[test]
fn transaction_script_rejects_missing_mast_and_invalid_entrypoint() {
    let missing_mast = proto::transaction::TransactionScript { entrypoint: 0, mast: None };
    let error = miden_protocol::transaction::TransactionScript::try_from(missing_mast).unwrap_err();
    assert!(error.to_string().ends_with("::mast is missing"));

    let invalid_entrypoint = proto::transaction::TransactionScript {
        entrypoint: 1,
        mast: Some(miden_protocol::MastForest::new().into()),
    };
    let error =
        miden_protocol::transaction::TransactionScript::try_from(invalid_entrypoint).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("failed to deserialize transaction_script.entrypoint: ")
    );
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
    let error =
        miden_protocol::transaction::TransactionScript::try_from(malformed_mast).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("mast.encoded: failed to deserialize MastForest: "),
        "{error}"
    );
    assert_matches!(
        error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<DeserializationError>()),
        Some(DeserializationError::UnexpectedEOF)
    );
}
