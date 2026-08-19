use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta};
use miden_protocol::crypto::merkle::smt::{LeafIndex, SmtLeaf, SmtProof};
use miden_protocol::crypto::merkle::{MerklePath, SparseMerklePath};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

// MERKLE PATH
// ================================================================================================

impl From<&MerklePath> for proto::primitives::MerklePath {
    fn from(value: &MerklePath) -> Self {
        let siblings = value.nodes().iter().map(proto::primitives::Digest::from).collect();
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

impl TryFrom<proto::primitives::MerklePath> for MerklePath {
    type Error = ConversionError;

    fn try_from(merkle_path: proto::primitives::MerklePath) -> Result<Self, Self::Error> {
        (&merkle_path).try_into()
    }
}

// SPARSE MERKLE PATH
// ================================================================================================

impl From<SparseMerklePath> for proto::primitives::SparseMerklePath {
    fn from(value: SparseMerklePath) -> Self {
        let (empty_nodes_mask, siblings) = value.into_parts();
        proto::primitives::SparseMerklePath {
            empty_nodes_mask,
            siblings: siblings.into_iter().map(proto::primitives::Digest::from).collect(),
        }
    }
}

impl TryFrom<proto::primitives::SparseMerklePath> for SparseMerklePath {
    type Error = ConversionError;

    fn try_from(merkle_path: proto::primitives::SparseMerklePath) -> Result<Self, Self::Error> {
        Ok(SparseMerklePath::from_parts(
            merkle_path.empty_nodes_mask,
            merkle_path
                .siblings
                .into_iter()
                .map(Word::try_from)
                .collect::<Result<Vec<_>, _>>()
                .context("siblings")?,
        )?)
    }
}

// MMR DELTA
// ================================================================================================

impl From<MmrDelta> for proto::primitives::MmrDelta {
    fn from(value: MmrDelta) -> Self {
        let data = value.data.into_iter().map(proto::primitives::Digest::from).collect();
        proto::primitives::MmrDelta {
            forest: value.forest.num_leaves() as u64,
            data,
        }
    }
}

impl TryFrom<proto::primitives::MmrDelta> for MmrDelta {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::MmrDelta) -> Result<Self, Self::Error> {
        let data: Vec<_> = value
            .data
            .into_iter()
            .map(Word::try_from)
            .collect::<Result<_, _>>()
            .context("data")?;

        let forest_size: usize =
            value.forest.try_into().context("forest size does not fit in usize")?;
        let forest = Forest::new(forest_size).context("forest size out of range")?;

        Ok(MmrDelta { forest, data })
    }
}

// SPARSE MERKLE TREE
// ================================================================================================

// SMT LEAF
// ------------------------------------------------------------------------------------------------

impl TryFrom<proto::primitives::SmtLeaf> for SmtLeaf {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::SmtLeaf) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let leaf = required!(decoder, value.leaf)?;

        match leaf {
            proto::primitives::smt_leaf::Leaf::EmptyLeafIndex(leaf_index) => {
                Ok(Self::new_empty(LeafIndex::new_max_depth(leaf_index)))
            },
            proto::primitives::smt_leaf::Leaf::Single(entry) => {
                let (key, value): (Word, Word) = entry.try_into().context("entry")?;

                Ok(SmtLeaf::new_single(key, value))
            },
            proto::primitives::smt_leaf::Leaf::Multiple(entries) => {
                let domain_entries: Vec<(Word, Word)> = entries
                    .entries
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()
                    .context("entries")?;

                Ok(SmtLeaf::new_multiple(domain_entries)?)
            },
        }
    }
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

impl TryFrom<proto::primitives::SmtLeafEntry> for (Word, Word) {
    type Error = ConversionError;

    fn try_from(entry: proto::primitives::SmtLeafEntry) -> Result<Self, Self::Error> {
        let decoder = entry.decoder();
        let key: Word = required!(decoder, entry.key)?;
        let value: Word = required!(decoder, entry.value)?;

        Ok((key, value))
    }
}

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

impl TryFrom<proto::primitives::SmtOpening> for SmtProof {
    type Error = ConversionError;

    fn try_from(opening: proto::primitives::SmtOpening) -> Result<Self, Self::Error> {
        let decoder = opening.decoder();
        let path: SparseMerklePath = required!(decoder, opening.path)?;
        let leaf: SmtLeaf = required!(decoder, opening.leaf)?;

        Ok(SmtProof::new(path, leaf)?)
    }
}

impl From<SmtProof> for proto::primitives::SmtOpening {
    fn from(proof: SmtProof) -> Self {
        let (path, leaf) = proof.into_parts();
        Self {
            path: Some(path.into()),
            leaf: Some(leaf.into()),
        }
    }
}
