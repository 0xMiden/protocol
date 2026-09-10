pub use proto::primitives::DecodedMerklePath as MerklePath;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for MerklePath {
    type Verified = miden_protocol::crypto::merkle::MerklePath;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.siblings))
    }
}

pub use proto::primitives::DecodedSparseMerklePath as SparseMerklePath;

impl Verify for SparseMerklePath {
    type Verified = miden_protocol::crypto::merkle::SparseMerklePath;
    type Error = miden_protocol::crypto::merkle::MerkleError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Self::Verified::from_parts(self.empty_nodes_mask, self.siblings)
    }
}

pub use proto::primitives::DecodedMmrDelta as MmrDelta;

impl Verify for MmrDelta {
    type Verified = miden_protocol::crypto::merkle::mmr::MmrDelta;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let forest = miden_protocol::crypto::merkle::mmr::Forest::new(self.forest.try_into()?)?;
        Ok(Self::Verified { forest, data: self.update_data })
    }
}
