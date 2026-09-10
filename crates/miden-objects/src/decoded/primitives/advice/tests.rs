use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use miden_protocol::{Felt, Word};

use crate::test_utils::dummy_word;
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn merkle_store_node_verifies() {
    let decoded = proto::primitives::MerkleStoreNode {
        value: Some(Word::empty().into()),
        left: Some(Word::empty().into()),
        right: Some(Word::empty().into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap().value, Word::empty());
}

#[test]
fn advice_map_entry_verifies() {
    let decoded = proto::primitives::AdviceMapEntry {
        key: Some(Word::empty().into()),
        values: vec![miden_protocol::Felt::ONE.into()],
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap(), (Word::empty(), vec![miden_protocol::Felt::ONE]));
}

#[test]
fn advice_stack_verifies_in_order() {
    let decoded = proto::primitives::AdviceStack {
        values: vec![miden_protocol::Felt::ONE.into(), miden_protocol::Felt::ZERO.into()],
    }
    .decode_fields()
    .unwrap();
    assert_eq!(
        decoded.verify().unwrap().iter().copied().collect::<Vec<_>>(),
        vec![miden_protocol::Felt::ONE, miden_protocol::Felt::ZERO]
    );
}

#[test]
fn advice_map_verification_rejects_duplicates_after_decoding() {
    let entry = proto::primitives::AdviceMapEntry {
        key: Some(Word::empty().into()),
        values: vec![],
    };
    let decoded = proto::primitives::AdviceMap { entries: vec![entry.clone(), entry] }
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.entries.len(), 2);
    assert!(
        matches!(decoded.verify(), Err(crate::decoded::primitives::AdviceError::DuplicateMapKey(key)) if key == Word::empty())
    );
}

#[test]
fn merkle_store_verification_rejects_duplicates_after_decoding() {
    let node = proto::primitives::MerkleStoreNode {
        value: Some(Word::empty().into()),
        left: Some(Word::empty().into()),
        right: Some(Word::empty().into()),
    };
    let decoded = proto::primitives::MerkleStore { nodes: vec![node.clone(), node] }
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.nodes.len(), 2);
    assert!(
        matches!(decoded.verify(), Err(crate::decoded::primitives::AdviceError::DuplicateMerkleParent(key)) if key == Word::empty())
    );
}

#[test]
fn advice_inputs_decode_nested_records_before_verification() {
    let input = miden_protocol::vm::AdviceInputs::default();
    let decoded = proto::primitives::AdviceInputs::from(&input).decode_fields().unwrap();
    assert!(decoded.advice_map.entries.is_empty());
    assert_eq!(decoded.verify().unwrap(), input);
}

#[test]
fn advice_map_decoding_normalizes_arbitrary_entry_order() {
    let map = proto::primitives::AdviceMap {
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
    }
    .decode_fields()
    .unwrap()
    .verify()
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
fn advice_map_rejects_duplicate_keys() {
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
    let error = duplicate
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_eq!(error.to_string(), format!("duplicate advice map key {}", dummy_word(1)));
}

#[test]
fn merkle_store_rejects_duplicate_parents() {
    let node = proto::primitives::MerkleStoreNode {
        value: Some(dummy_word(1).into()),
        left: Some(dummy_word(2).into()),
        right: Some(dummy_word(3).into()),
    };
    let duplicate = proto::primitives::MerkleStore { nodes: vec![node.clone(), node] };
    let error = duplicate
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();
    assert_eq!(error.to_string(), format!("duplicate Merkle store parent {}", dummy_word(1)));
}
