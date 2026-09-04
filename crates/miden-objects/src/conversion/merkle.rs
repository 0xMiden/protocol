use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta};
use miden_protocol::crypto::merkle::smt::{
    LeafIndex,
    PartialSmt,
    SMT_DEPTH,
    SmtLeaf,
    SmtProof,
    UniqueNodes,
};
use miden_protocol::crypto::merkle::{MerklePath, NodeIndex, SparseMerklePath};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

// MERKLE PATH
// ================================================================================================

impl From<&MerklePath> for proto::primitives::MerklePath {
    fn from(value: &MerklePath) -> Self {
        let siblings = value.nodes().iter().map(Into::into).collect();
        proto::primitives::MerklePath { siblings }
    }
}

impl From<MerklePath> for proto::primitives::MerklePath {
    fn from(value: MerklePath) -> Self {
        (&value).into()
    }
}

impl TryFrom<&proto::primitives::MerklePath> for MerklePath {
    type Error = ConversionError;

    fn try_from(merkle_path: &proto::primitives::MerklePath) -> Result<Self, Self::Error> {
        merkle_path.siblings.iter().map(Word::try_from).collect()
    }
}

// SPARSE MERKLE PATH
// ================================================================================================

impl From<SparseMerklePath> for proto::primitives::SparseMerklePath {
    fn from(value: SparseMerklePath) -> Self {
        let (empty_nodes_mask, siblings) = value.into_parts();
        proto::primitives::SparseMerklePath {
            empty_nodes_mask,
            siblings: siblings.into_iter().map(Into::into).collect(),
        }
    }
}

// MMR DELTA
// ================================================================================================

impl From<MmrDelta> for proto::primitives::MmrDelta {
    fn from(value: MmrDelta) -> Self {
        let update_data = value.data.into_iter().map(Into::into).collect();
        proto::primitives::MmrDelta {
            forest: value.forest.num_leaves() as u64,
            update_data,
        }
    }
}

pub(crate) fn decode_mmr_delta(
    forest: u64,
    update_data: Vec<Word>,
) -> Result<MmrDelta, ConversionError> {
    let forest_size = forest.try_into().context("forest size does not fit in usize")?;
    let forest = Forest::new(forest_size).context("forest size out of range")?;

    Ok(MmrDelta { forest, data: update_data })
}

// SPARSE MERKLE TREE
// ================================================================================================

// SMT LEAF
// ------------------------------------------------------------------------------------------------

pub(crate) fn decode_empty_smt_leaf(leaf_index: u64) -> SmtLeaf {
    SmtLeaf::new_empty(LeafIndex::new_max_depth(leaf_index))
}

impl From<SmtLeaf> for proto::primitives::SmtLeaf {
    fn from(smt_leaf: SmtLeaf) -> Self {
        use proto::primitives::smt_leaf::Leaf;

        let leaf = match smt_leaf {
            SmtLeaf::Empty(leaf_index) => Leaf::EmptyLeafIndex(leaf_index.position()),
            SmtLeaf::Single(entry) => Leaf::Single(entry.into()),
            SmtLeaf::Multiple(entries) => Leaf::Multiple(proto::primitives::SmtLeafEntryList {
                entries: entries.into_iter().map(Into::into).collect(),
            }),
        };

        Self { leaf: Some(leaf) }
    }
}

// SMT LEAF ENTRY
// ------------------------------------------------------------------------------------------------

impl From<(Word, Word)> for proto::primitives::SmtLeafEntry {
    fn from((key, value): (Word, Word)) -> Self {
        Self {
            key: Some(key.into()),
            value: Some(value.into()),
        }
    }
}

// SMT PROOF
// ------------------------------------------------------------------------------------------------

impl From<SmtProof> for proto::primitives::SmtOpening {
    fn from(proof: SmtProof) -> Self {
        let (path, leaf) = proof.into_parts();
        Self {
            path: Some(path.into()),
            leaf: Some(leaf.into()),
        }
    }
}

// PARTIAL SMT
// ------------------------------------------------------------------------------------------------

impl From<UniqueNodes> for proto::primitives::PartialSmt {
    fn from(unique_nodes: UniqueNodes) -> Self {
        let UniqueNodes { root, nodes, leaves, value_only_leaves } = unique_nodes;

        let mut node_levels = Vec::new();
        let mut nodes = nodes.into_iter().peekable();
        while let Some((index, _)) = nodes.peek() {
            let depth = index.depth();
            let mut level_nodes = Vec::new();
            while let Some((index, digest)) = nodes.next_if(|(index, _)| index.depth() == depth) {
                level_nodes.push(proto::primitives::PartialSmtNode {
                    index: index.position(),
                    digest: Some(digest.into()),
                });
            }
            node_levels.push(proto::primitives::PartialSmtNodeLevel {
                depth: u32::from(depth),
                nodes: level_nodes,
            });
        }
        let leaves = leaves
            .into_iter()
            .map(|(index, leaf)| proto::primitives::IndexedSmtLeaf {
                index,
                leaf: Some(leaf.into()),
            })
            .collect();

        let value_only_leaves = value_only_leaves
            .into_iter()
            .map(|(index, value)| proto::primitives::IndexedDigest {
                index,
                value: Some(value.into()),
            })
            .collect();

        Self {
            root: Some(root.into()),
            node_levels,
            leaves,
            value_only_leaves,
        }
    }
}

impl TryFrom<proto::primitives::PartialSmt> for UniqueNodes {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::PartialSmt) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let proto::primitives::PartialSmt {
            root,
            node_levels,
            leaves,
            value_only_leaves,
        } = value;

        let root = required!(decoder, root)?;

        let mut seen_depths = BTreeSet::new();
        let mut decoded_nodes = BTreeMap::new();
        for level in node_levels {
            let depth = u8::try_from(level.depth).context("node_levels.depth")?;
            if depth == 0 || depth >= SMT_DEPTH {
                return Err(ConversionError::message(format!(
                    "partial SMT node depth {depth} must be in the range 1..{SMT_DEPTH}"
                )));
            }
            if !seen_depths.insert(depth) {
                return Err(ConversionError::message(format!(
                    "partial SMT contains duplicate node depth {depth}"
                )));
            }

            for node in level.nodes {
                let index = NodeIndex::new(depth, node.index).context("node_levels.nodes.index")?;
                if decoded_nodes.contains_key(&index) {
                    return Err(ConversionError::message(format!(
                        "partial SMT contains duplicate node index {} at depth {depth}",
                        node.index
                    )));
                }
                let digest = node.digest.ok_or_else(|| {
                    ConversionError::missing_field::<proto::primitives::PartialSmtNode>("digest")
                })?;
                decoded_nodes.insert(index, digest.try_into().context("digest")?);
            }
        }

        let mut seen_leaf_indices = BTreeSet::new();
        let mut decoded_leaves = BTreeMap::new();
        for indexed_leaf in leaves {
            if !seen_leaf_indices.insert(indexed_leaf.index) {
                return Err(ConversionError::message(format!(
                    "partial SMT contains duplicate leaf index {}",
                    indexed_leaf.index
                )));
            }
            let decoder = indexed_leaf.decoder();
            let leaf = required!(decoder, indexed_leaf.leaf)?;
            decoded_leaves.insert(indexed_leaf.index, leaf);
        }

        let mut seen_value_only_indices = BTreeSet::new();
        let mut decoded_value_only_leaves = BTreeMap::new();
        for indexed_digest in value_only_leaves {
            if !seen_value_only_indices.insert(indexed_digest.index) {
                return Err(ConversionError::message(format!(
                    "partial SMT contains duplicate value-only leaf index {}",
                    indexed_digest.index
                )));
            }
            if seen_leaf_indices.contains(&indexed_digest.index) {
                return Err(ConversionError::message(format!(
                    "partial SMT leaf index {} has both a leaf and a value-only leaf",
                    indexed_digest.index
                )));
            }
            let decoder = indexed_digest.decoder();
            let digest = required!(decoder, indexed_digest.value)?;
            decoded_value_only_leaves.insert(indexed_digest.index, digest);
        }

        Ok(UniqueNodes {
            root,
            nodes: decoded_nodes,
            leaves: decoded_leaves,
            value_only_leaves: decoded_value_only_leaves,
        })
    }
}

impl From<PartialSmt> for proto::primitives::PartialSmt {
    fn from(partial_smt: PartialSmt) -> Self {
        partial_smt.to_unique_nodes().into()
    }
}

impl TryFrom<proto::primitives::PartialSmt> for PartialSmt {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::PartialSmt) -> Result<Self, Self::Error> {
        let unique_nodes = UniqueNodes::try_from(value)?;
        PartialSmt::from_unique_nodes(unique_nodes)
            .map_err(|err| ConversionError::deserialization("PartialSmt", err))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;

    use miden_protocol::crypto::merkle::smt::{PartialSmt, Smt, UniqueNodes};
    use prost::Message;

    use super::*;

    #[test]
    fn mmr_delta_roundtrips_and_reports_update_index() {
        let data = vec![Word::from([1, 2, 3, 4_u32])];
        let delta = MmrDelta {
            forest: Forest::new(3).unwrap(),
            data: data.clone(),
        };
        let message: proto::primitives::MmrDelta = delta.into();
        let decoded = MmrDelta::try_from(message).unwrap();
        assert_eq!(decoded.forest.num_leaves(), 3);
        assert_eq!(decoded.data, data);

        let invalid = proto::primitives::MmrDelta {
            forest: 0,
            update_data: vec![proto::primitives::Word { encoded: vec![0; 31] }],
        };
        let error = MmrDelta::try_from(invalid).unwrap_err();
        assert!(error.to_string().starts_with("update_data[0]."));
    }

    #[test]
    fn partial_smt_round_trip() {
        let key0 = Word::from([1, 2, 3, 4u32]);
        let key1 = Word::from([5, 6, 7, 8u32]);
        let missing_key = Word::from([9, 10, 11, 12u32]);
        let value0 = Word::from([13, 14, 15, 16u32]);
        let value1 = Word::from([17, 18, 19, 20u32]);
        let smt = Smt::with_entries([(key0, value0), (key1, value1)]).unwrap();
        let partial_smt =
            PartialSmt::from_proofs([smt.open(&key0), smt.open(&missing_key)]).unwrap();

        let encoded: proto::primitives::PartialSmt = partial_smt.clone().into();
        assert!(encoded.node_levels.is_sorted_by_key(|level| level.depth));

        let decoded = PartialSmt::try_from(encoded).unwrap();

        assert_eq!(decoded, partial_smt);
        assert_eq!(decoded.get_value(&key0).unwrap(), value0);
        assert_eq!(decoded.get_value(&missing_key).unwrap(), Word::empty());
    }

    #[test]
    fn smt_leaf_roundtrips_all_variants() {
        let entries = vec![
            (Word::from([1, 2, 3, 4_u32]), Word::from([5, 6, 7, 8_u32])),
            (Word::from([9, 10, 11, 4_u32]), Word::from([12, 13, 14, 15_u32])),
        ];
        let leaves = [
            SmtLeaf::new_empty(LeafIndex::new_max_depth(7)),
            SmtLeaf::new_single(entries[0].0, entries[0].1),
            SmtLeaf::new_multiple(entries).unwrap(),
        ];

        for leaf in leaves {
            let encoded: proto::primitives::SmtLeaf = leaf.clone().into();
            assert_eq!(SmtLeaf::try_from(encoded).unwrap(), leaf);
        }
    }

    #[test]
    fn smt_leaf_reports_nested_entry_paths() {
        use proto::primitives::smt_leaf::Leaf;

        let encoded = proto::primitives::SmtLeaf {
            leaf: Some(Leaf::Multiple(proto::primitives::SmtLeafEntryList {
                entries: vec![
                    proto::primitives::SmtLeafEntry {
                        key: Some(Word::empty().into()),
                        value: Some(Word::empty().into()),
                    },
                    proto::primitives::SmtLeafEntry {
                        key: Some(Word::empty().into()),
                        value: Some(proto::primitives::Word { encoded: vec![0; 31] }),
                    },
                ],
            })),
        };

        let error = SmtLeaf::try_from(encoded).unwrap_err();
        assert!(
            error.to_string().starts_with("leaf.multiple.entries[1].value.word.encoded:"),
            "{error}"
        );
    }

    #[test]
    fn smt_leaf_reports_multiple_leaf_invariants_at_the_variant() {
        use proto::primitives::smt_leaf::Leaf;

        let encoded = proto::primitives::SmtLeaf {
            leaf: Some(Leaf::Multiple(proto::primitives::SmtLeafEntryList {
                entries: vec![proto::primitives::SmtLeafEntry {
                    key: Some(Word::empty().into()),
                    value: Some(Word::empty().into()),
                }],
            })),
        };

        let error = SmtLeaf::try_from(encoded).unwrap_err();
        assert!(error.to_string().starts_with("leaf.multiple:"));
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
        let decoded = UniqueNodes::try_from(encoded).unwrap();
        assert_eq!(decoded.nodes, expected_nodes);
    }

    fn empty_partial_smt_message() -> proto::primitives::PartialSmt {
        proto::primitives::PartialSmt {
            root: Some(PartialSmt::EMPTY_ROOT.into()),
            node_levels: vec![],
            leaves: vec![],
            value_only_leaves: vec![],
        }
    }

    fn assert_partial_smt_decode_error(
        encoded: proto::primitives::PartialSmt,
        expected_error: &str,
    ) {
        let error = PartialSmt::try_from(encoded).unwrap_err();
        assert_eq!(error.to_string(), expected_error);
    }

    #[test]
    fn partial_smt_rejects_missing_root() {
        let mut encoded = empty_partial_smt_message();
        encoded.root = None;
        assert_partial_smt_decode_error(
            encoded,
            "field miden_objects::proto::primitives::PartialSmt::root is missing",
        );
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
        assert_partial_smt_decode_error(
            encoded,
            "node_levels.nodes.index: node index position 2 is not valid for depth 1",
        );
    }

    #[test]
    fn partial_smt_rejects_missing_node_digest() {
        let mut encoded = empty_partial_smt_message();
        encoded.node_levels = vec![proto::primitives::PartialSmtNodeLevel {
            depth: 1,
            nodes: vec![proto::primitives::PartialSmtNode { index: 0, digest: None }],
        }];
        assert_partial_smt_decode_error(
            encoded,
            "field miden_objects::proto::primitives::PartialSmtNode::digest is missing",
        );
    }

    #[test]
    fn partial_smt_rejects_missing_leaf() {
        let mut encoded = empty_partial_smt_message();
        encoded.leaves = vec![proto::primitives::IndexedSmtLeaf { index: 0, leaf: None }];
        assert_partial_smt_decode_error(
            encoded,
            "field miden_objects::proto::primitives::IndexedSmtLeaf::leaf is missing",
        );
    }

    #[test]
    fn partial_smt_rejects_missing_value_only_leaf() {
        let mut encoded = empty_partial_smt_message();
        encoded.value_only_leaves =
            vec![proto::primitives::IndexedDigest { index: 0, value: None }];
        assert_partial_smt_decode_error(
            encoded,
            "field miden_objects::proto::primitives::IndexedDigest::value is missing",
        );
    }

    #[test]
    fn partial_smt_rejects_depth_overflow() {
        let mut encoded = empty_partial_smt_message();
        encoded.node_levels =
            vec![proto::primitives::PartialSmtNodeLevel { depth: 256, nodes: vec![] }];
        assert_partial_smt_decode_error(
            encoded,
            "node_levels.depth: out of range integral type conversion attempted",
        );
    }

    #[test]
    fn partial_smt_rejects_zero_depth() {
        let mut encoded = empty_partial_smt_message();
        encoded.node_levels =
            vec![proto::primitives::PartialSmtNodeLevel { depth: 0, nodes: vec![] }];
        assert_partial_smt_decode_error(
            encoded,
            "partial SMT node depth 0 must be in the range 1..64",
        );
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
            "failed to deserialize PartialSmt: invalid value: Node index 0 did not match the embedded leaf index 1",
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
            "failed to deserialize PartialSmt: invalid value: inner node hash is inconsistent with parent",
        );
    }
}
