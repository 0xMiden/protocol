use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::crypto::merkle::mmr::MmrDelta;
use miden_protocol::crypto::merkle::smt::{PartialSmt, SmtLeaf, SmtProof, UniqueNodes};
use miden_protocol::crypto::merkle::{MerklePath, SparseMerklePath};

use crate::proto;

#[cfg(test)]
mod tests;

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

// SPARSE MERKLE TREE
// ================================================================================================

// SMT LEAF
// ------------------------------------------------------------------------------------------------

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

impl From<PartialSmt> for proto::primitives::PartialSmt {
    fn from(partial_smt: PartialSmt) -> Self {
        partial_smt.to_unique_nodes().into()
    }
}
