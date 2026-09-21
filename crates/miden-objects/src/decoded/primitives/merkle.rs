pub use proto::primitives::DecodedMerklePath as MerklePath;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for MerklePath {
    type Verified = miden_protocol::crypto::merkle::MerklePath;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.siblings.into_inner()))
    }
}

pub use proto::primitives::DecodedSparseMerklePath as SparseMerklePath;

impl Verify for SparseMerklePath {
    type Verified = miden_protocol::crypto::merkle::SparseMerklePath;
    type Error = miden_protocol::crypto::merkle::MerkleError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Self::Verified::from_parts(self.empty_nodes_mask, self.siblings.into_inner())
    }
}

pub use proto::primitives::DecodedMmrDelta as MmrDelta;

impl Verify for MmrDelta {
    type Verified = miden_protocol::crypto::merkle::mmr::MmrDelta;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let forest = miden_protocol::crypto::merkle::mmr::Forest::new(self.forest.try_into()?)?;
        Ok(Self::Verified {
            forest,
            data: self.update_data.into_inner(),
        })
    }
}

pub use proto::primitives::DecodedTrackedMmrLeaf as TrackedMmrLeaf;

impl Verify for TrackedMmrLeaf {
    type Verified = (u64, miden_protocol::Word, alloc::vec::Vec<miden_protocol::Word>);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.position, self.leaf, self.path.into_inner()))
    }
}

pub use proto::primitives::DecodedPartialMmr as PartialMmr;

/// Checks reconstruction against the supplied peaks without authenticating those peaks.
impl Verify for PartialMmr {
    type Verified = miden_protocol::crypto::merkle::mmr::PartialMmr;
    type Error = VerificationError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::crypto::merkle::MerklePath;
        use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};

        let size = usize::try_from(self.forest)?;
        let peaks = MmrPeaks::new(Forest::new(size)?, self.peaks.into_inner())?;
        let leaves = self.tracked_leaves.into_inner();

        if !leaves.is_sorted_by(|a, b| a.position < b.position) {
            return Err(PartialMmrError::LeafOrder.into());
        }

        if let Some(last_leaf) = leaves.iter().last() {
            let last_position = usize::try_from(last_leaf.position)?;
            if last_position >= size {
                return Err(PartialMmrError::Position { position: last_position, size }.into());
            }
        }

        let mut mmr = PartialMmr::from_peaks(peaks);
        for tracked in leaves {
            let position = usize::try_from(tracked.position)?;
            mmr.track(position, tracked.leaf, &MerklePath::new(tracked.path.into_inner()))?;
        }
        Ok(mmr)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PartialMmrError {
    #[error("tracked leaf position {position} is outside forest of size {size}")]
    Position { position: usize, size: usize },
    #[error("tracked leaf positions must be unique and strictly increasing")]
    LeafOrder,
}
