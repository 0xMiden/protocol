use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::crypto::merkle::NodeIndex;
use miden_protocol::crypto::merkle::smt::{LeafIndex, PartialSmt, Smt, SmtLeaf, UniqueNodes};
use prost::Message;

use crate::{DecodeMessage, Verify, proto};

#[test]
fn partial_smt_round_trip() {
    let key0 = Word::from([1, 2, 3, 4u32]);
    let key1 = Word::from([5, 6, 7, 8u32]);
    let missing_key = Word::from([9, 10, 11, 12u32]);
    let value0 = Word::from([13, 14, 15, 16u32]);
    let value1 = Word::from([17, 18, 19, 20u32]);
    let smt = Smt::with_entries([(key0, value0), (key1, value1)]).unwrap();
    let partial_smt = PartialSmt::from_proofs([smt.open(&key0), smt.open(&missing_key)]).unwrap();

    let encoded: proto::primitives::PartialSmt = partial_smt.clone().into();
    assert!(encoded.node_levels.is_sorted_by_key(|level| level.depth));

    let decoded = encoded.decode_fields().unwrap().verify().unwrap();

    assert_eq!(decoded, partial_smt);
    assert_eq!(decoded.get_value(&key0).unwrap(), value0);
    assert_eq!(decoded.get_value(&missing_key).unwrap(), Word::empty());
}

#[test]
fn partial_smt_encoding_is_canonical_for_equivalent_unique_nodes() {
    let mut first = UniqueNodes::empty();
    first.nodes.insert(NodeIndex::new(1, 1).unwrap(), Word::from([1, 2, 3, 4u32]));
    first
        .nodes
        .insert(NodeIndex::new(1, 0).unwrap(), Word::from([9, 10, 11, 12u32]));
    first.leaves = BTreeMap::from([
        (2, SmtLeaf::new_empty(LeafIndex::new_max_depth(2))),
        (1, SmtLeaf::new_empty(LeafIndex::new_max_depth(1))),
    ]);
    first.value_only_leaves =
        BTreeMap::from([(2, Word::from([5, 6, 7, 8u32])), (1, Word::from([9, 10, 11, 12u32]))]);

    let mut second = first.clone();
    second.nodes = BTreeMap::from([
        (NodeIndex::new(1, 0).unwrap(), Word::from([9, 10, 11, 12u32])),
        (NodeIndex::new(1, 1).unwrap(), Word::from([1, 2, 3, 4u32])),
    ]);
    second.leaves = BTreeMap::from([
        (1, SmtLeaf::new_empty(LeafIndex::new_max_depth(1))),
        (2, SmtLeaf::new_empty(LeafIndex::new_max_depth(2))),
    ]);
    second.value_only_leaves =
        BTreeMap::from([(1, Word::from([9, 10, 11, 12u32])), (2, Word::from([5, 6, 7, 8u32]))]);

    let first: proto::primitives::PartialSmt = first.into();
    let second: proto::primitives::PartialSmt = second.into();

    assert_eq!(first, second);
    assert_eq!(first.encode_to_vec(), second.encode_to_vec());
}

#[test]
fn partial_smt_encoding_preserves_nodes_at_every_depth() {
    let expected_nodes = BTreeMap::from([
        (NodeIndex::new(1, 0).unwrap(), Word::from([1, 2, 3, 4u32])),
        (NodeIndex::new(1, 1).unwrap(), Word::from([5, 6, 7, 8u32])),
        (NodeIndex::new(2, 0).unwrap(), Word::from([9, 10, 11, 12u32])),
        (NodeIndex::new(2, 3).unwrap(), Word::from([13, 14, 15, 16u32])),
        (NodeIndex::new(3, 5).unwrap(), Word::from([17, 18, 19, 20u32])),
    ]);
    let mut unique_nodes = UniqueNodes::empty();
    unique_nodes.nodes = expected_nodes.clone();

    let encoded: proto::primitives::PartialSmt = unique_nodes.into();

    assert_eq!(
        encoded.node_levels.iter().map(|level| level.depth).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let decoded = encoded.decode_fields().unwrap().into_unique_nodes().unwrap();
    assert_eq!(decoded.nodes, expected_nodes);
}
