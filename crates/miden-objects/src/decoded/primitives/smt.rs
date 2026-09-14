use miden_protobuf::unwrap_infallible;
pub use proto::primitives::DecodedSmtLeafEntry as SmtLeafEntry;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for SmtLeafEntry {
    type Verified = (miden_protocol::Word, miden_protocol::Word);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.key, self.value))
    }
}

pub use proto::primitives::DecodedPartialSmtNode as PartialSmtNode;

impl Verify for PartialSmtNode {
    type Verified = (u64, miden_protocol::Word);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.index, self.digest))
    }
}

pub use proto::primitives::DecodedPartialSmtNodeLevel as PartialSmtNodeLevel;

impl Verify for PartialSmtNodeLevel {
    type Verified = (u32, alloc::vec::Vec<(u64, miden_protocol::Word)>);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((
            self.depth,
            self.nodes.into_iter().map(Verify::verify).collect::<Result<_, _>>()?,
        ))
    }
}

pub use proto::primitives::DecodedIndexedDigest as IndexedDigest;

impl Verify for IndexedDigest {
    type Verified = (u64, miden_protocol::Word);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.index, self.value))
    }
}

pub use proto::primitives::DecodedSmtLeafEntryList as SmtLeafEntryList;

impl Verify for SmtLeafEntryList {
    type Verified = alloc::vec::Vec<(miden_protocol::Word, miden_protocol::Word)>;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.entries.into_iter().map(Verify::verify).collect()
    }
}

pub use proto::primitives::DecodedSmtLeaf as SmtLeaf;

impl Verify for SmtLeaf {
    type Verified = miden_protocol::crypto::merkle::smt::SmtLeaf;
    type Error = miden_protocol::crypto::merkle::smt::SmtLeafError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::crypto::merkle::smt::LeafIndex;
        use proto::primitives::smt_leaf::DecodedLeaf;
        match self.leaf {
            DecodedLeaf::EmptyLeafIndex(index) => {
                Ok(Self::Verified::new_empty(LeafIndex::new_max_depth(index)))
            },
            DecodedLeaf::Single(entry) => Ok(Self::Verified::new_single(entry.key, entry.value)),
            DecodedLeaf::Multiple(entries) => {
                Self::Verified::new_multiple(unwrap_infallible(entries.verify()))
            },
        }
    }
}

pub use proto::primitives::DecodedIndexedSmtLeaf as IndexedSmtLeaf;

impl Verify for IndexedSmtLeaf {
    type Verified = (u64, miden_protocol::crypto::merkle::smt::SmtLeaf);
    type Error = miden_protocol::crypto::merkle::smt::SmtLeafError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.index, self.leaf.verify()?))
    }
}

pub use proto::primitives::DecodedSmtOpening as SmtOpening;

impl Verify for SmtOpening {
    type Verified = miden_protocol::crypto::merkle::smt::SmtProof;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.path.verify()?, self.leaf.verify()?)?)
    }
}

pub use proto::primitives::DecodedPartialSmt as PartialSmt;

impl Verify for PartialSmt {
    type Verified = miden_protocol::crypto::merkle::smt::PartialSmt;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::from_unique_nodes(self.into_unique_nodes()?)?)
    }
}

impl PartialSmt {
    /// Checks duplicate indices and constructs reconstruction input, without checking its root.
    pub fn into_unique_nodes(
        self,
    ) -> Result<miden_protocol::crypto::merkle::smt::UniqueNodes, VerificationError> {
        use alloc::collections::{BTreeMap, BTreeSet};

        use miden_protocol::crypto::merkle::NodeIndex;
        use miden_protocol::crypto::merkle::smt::{SMT_DEPTH, UniqueNodes};
        let mut depths = BTreeSet::new();
        let mut nodes = BTreeMap::new();
        for level in self.node_levels {
            let depth = u8::try_from(level.depth)?;
            if depth == 0 || depth >= SMT_DEPTH {
                return Err(PartialSmtError::Depth(depth).into());
            }
            if !depths.insert(depth) {
                return Err(PartialSmtError::DuplicateDepth(depth).into());
            }
            for node in level.nodes {
                let index = NodeIndex::new(depth, node.index)?;
                if nodes.insert(index, node.digest).is_some() {
                    return Err(PartialSmtError::DuplicateNode { index: node.index, depth }.into());
                }
            }
        }
        let mut leaves = BTreeMap::new();
        for indexed in self.leaves {
            let (index, leaf) = indexed.verify()?;
            if leaves.insert(index, leaf).is_some() {
                return Err(PartialSmtError::DuplicateLeaf(index).into());
            }
        }
        let mut value_only_leaves = BTreeMap::new();
        for indexed in self.value_only_leaves {
            if leaves.contains_key(&indexed.index) {
                return Err(PartialSmtError::OverlappingLeaf(indexed.index).into());
            }
            if value_only_leaves.insert(indexed.index, indexed.value).is_some() {
                return Err(PartialSmtError::DuplicateValueOnlyLeaf(indexed.index).into());
            }
        }
        Ok(UniqueNodes {
            root: self.root,
            nodes,
            leaves,
            value_only_leaves,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PartialSmtError {
    #[error("partial SMT node depth {0} must be in the range 1..64")]
    Depth(u8),
    #[error("partial SMT contains duplicate node depth {0}")]
    DuplicateDepth(u8),
    #[error("partial SMT contains duplicate node index {index} at depth {depth}")]
    DuplicateNode { index: u64, depth: u8 },
    #[error("partial SMT contains duplicate leaf index {0}")]
    DuplicateLeaf(u64),
    #[error("partial SMT contains duplicate value-only leaf index {0}")]
    DuplicateValueOnlyLeaf(u64),
    #[error("partial SMT leaf index {0} has both a leaf and a value-only leaf")]
    OverlappingLeaf(u64),
}
