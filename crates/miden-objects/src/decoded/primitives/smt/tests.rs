use alloc::string::ToString;
use alloc::vec;

use miden_protocol::Word;
use miden_protocol::crypto::merkle::smt::{LeafIndex, PartialSmt, SMT_DEPTH, SmtLeaf};

use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn smt_leaf_entry_verifies() {
    let decoded = proto::primitives::SmtLeafEntry {
        key: Some(Word::empty().into()),
        value: Some(Word::empty().into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap(), (Word::empty(), Word::empty()));
}

#[test]
fn partial_smt_node_verifies() {
    assert_eq!(
        proto::primitives::PartialSmtNode {
            index: 7,
            digest: Some(Word::empty().into())
        }
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap(),
        (7, Word::empty())
    );
}

#[test]
fn partial_smt_level_verifies_nested_nodes() {
    let decoded = proto::primitives::PartialSmtNodeLevel {
        depth: 2,
        nodes: vec![proto::primitives::PartialSmtNode {
            index: 3,
            digest: Some(Word::empty().into()),
        }],
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap(), (2, vec![(3, Word::empty())]));
}

#[test]
fn indexed_digest_verifies() {
    assert_eq!(
        proto::primitives::IndexedDigest {
            index: 5,
            value: Some(Word::empty().into())
        }
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap(),
        (5, Word::empty())
    );
}

#[test]
fn smt_entry_list_verifies() {
    assert!(
        proto::primitives::SmtLeafEntryList { entries: vec![] }
            .decode_fields()
            .unwrap()
            .verify()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn smt_leaf_defers_multiple_entry_count_validation() {
    let wire = proto::primitives::SmtLeaf {
        leaf: Some(proto::primitives::smt_leaf::Leaf::Multiple(
            proto::primitives::SmtLeafEntryList { entries: vec![] },
        )),
    };
    assert!(wire.decode_fields().unwrap().verify().is_err());
}

fn empty_partial_smt_message() -> proto::primitives::PartialSmt {
    proto::primitives::PartialSmt {
        root: Some(PartialSmt::EMPTY_ROOT.into()),
        node_levels: vec![],
        leaves: vec![],
        value_only_leaves: vec![],
    }
}

fn assert_partial_smt_decode_error(encoded: proto::primitives::PartialSmt, expected_error: &str) {
    let error = encoded
        .decode_fields()
        .and_then(|decoded| decoded.verify().map_err(ConversionError::new))
        .unwrap_err();
    assert_eq!(error.to_string(), expected_error);
}

#[test]
fn partial_smt_rejects_duplicate_depth() {
    let mut encoded = empty_partial_smt_message();
    encoded.node_levels = vec![
        proto::primitives::PartialSmtNodeLevel { depth: 1, nodes: vec![] },
        proto::primitives::PartialSmtNodeLevel { depth: 1, nodes: vec![] },
    ];
    assert_partial_smt_decode_error(encoded, "partial SMT contains duplicate node depth 1");
}

#[test]
fn partial_smt_rejects_invalid_node_index() {
    let mut encoded = empty_partial_smt_message();
    encoded.node_levels = vec![proto::primitives::PartialSmtNodeLevel {
        depth: 1,
        nodes: vec![proto::primitives::PartialSmtNode {
            index: 2,
            digest: Some(Word::empty().into()),
        }],
    }];
    assert_partial_smt_decode_error(encoded, "node index position 2 is not valid for depth 1");
}

#[test]
fn partial_smt_rejects_depth_overflow() {
    let mut encoded = empty_partial_smt_message();
    encoded.node_levels =
        vec![proto::primitives::PartialSmtNodeLevel { depth: 256, nodes: vec![] }];
    assert_partial_smt_decode_error(encoded, "out of range integral type conversion attempted");
}

#[test]
fn partial_smt_rejects_zero_depth() {
    let mut encoded = empty_partial_smt_message();
    encoded.node_levels = vec![proto::primitives::PartialSmtNodeLevel { depth: 0, nodes: vec![] }];
    assert_partial_smt_decode_error(encoded, "partial SMT node depth 0 must be in the range 1..64");
}

#[test]
fn partial_smt_rejects_smt_depth() {
    let mut encoded = empty_partial_smt_message();
    encoded.node_levels = vec![proto::primitives::PartialSmtNodeLevel {
        depth: u32::from(SMT_DEPTH),
        nodes: vec![],
    }];
    assert_partial_smt_decode_error(
        encoded,
        "partial SMT node depth 64 must be in the range 1..64",
    );
}

#[test]
fn partial_smt_rejects_duplicate_node_index() {
    let mut encoded = empty_partial_smt_message();
    encoded.node_levels = vec![proto::primitives::PartialSmtNodeLevel {
        depth: 1,
        nodes: vec![
            proto::primitives::PartialSmtNode {
                index: 0,
                digest: Some(Word::empty().into()),
            },
            proto::primitives::PartialSmtNode {
                index: 0,
                digest: Some(Word::empty().into()),
            },
        ],
    }];
    assert_partial_smt_decode_error(
        encoded,
        "partial SMT contains duplicate node index 0 at depth 1",
    );
}

#[test]
fn partial_smt_rejects_duplicate_leaf_index() {
    let mut encoded = empty_partial_smt_message();
    encoded.leaves = vec![
        proto::primitives::IndexedSmtLeaf {
            index: 0,
            leaf: Some(SmtLeaf::new_empty(LeafIndex::new_max_depth(0)).into()),
        },
        proto::primitives::IndexedSmtLeaf {
            index: 0,
            leaf: Some(SmtLeaf::new_empty(LeafIndex::new_max_depth(0)).into()),
        },
    ];
    assert_partial_smt_decode_error(encoded, "partial SMT contains duplicate leaf index 0");
}

#[test]
fn partial_smt_rejects_duplicate_value_only_leaf_index() {
    let mut encoded = empty_partial_smt_message();
    encoded.value_only_leaves = vec![
        proto::primitives::IndexedDigest {
            index: 0,
            value: Some(Word::empty().into()),
        },
        proto::primitives::IndexedDigest {
            index: 0,
            value: Some(Word::empty().into()),
        },
    ];
    assert_partial_smt_decode_error(
        encoded,
        "partial SMT contains duplicate value-only leaf index 0",
    );
}

#[test]
fn partial_smt_rejects_overlapping_leaf_index() {
    let mut encoded = empty_partial_smt_message();
    encoded.leaves = vec![proto::primitives::IndexedSmtLeaf {
        index: 0,
        leaf: Some(SmtLeaf::new_empty(LeafIndex::new_max_depth(0)).into()),
    }];
    encoded.value_only_leaves = vec![proto::primitives::IndexedDigest {
        index: 0,
        value: Some(Word::empty().into()),
    }];
    assert_partial_smt_decode_error(
        encoded,
        "partial SMT leaf index 0 has both a leaf and a value-only leaf",
    );
}

#[test]
fn partial_smt_rejects_embedded_leaf_index_mismatch() {
    let mut encoded = empty_partial_smt_message();
    encoded.leaves = vec![proto::primitives::IndexedSmtLeaf {
        index: 0,
        leaf: Some(SmtLeaf::new_empty(LeafIndex::new_max_depth(1)).into()),
    }];
    assert_partial_smt_decode_error(
        encoded,
        "invalid value: Node index 0 did not match the embedded leaf index 1",
    );
}

#[test]
fn partial_smt_rejects_reconstruction_missing_node() {
    let mut encoded = empty_partial_smt_message();
    encoded.node_levels = vec![proto::primitives::PartialSmtNodeLevel {
        depth: 1,
        nodes: vec![proto::primitives::PartialSmtNode {
            index: 0,
            digest: Some(Word::empty().into()),
        }],
    }];
    assert_partial_smt_decode_error(
        encoded,
        "invalid value: inner node hash is inconsistent with parent",
    );
}
