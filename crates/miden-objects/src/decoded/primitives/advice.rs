use miden_protobuf::unwrap_infallible;
pub use proto::primitives::DecodedMerkleStoreNode as MerkleStoreNode;

use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for MerkleStoreNode {
    type Verified = miden_protocol::crypto::merkle::InnerNodeInfo;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified {
            value: self.value,
            left: self.left,
            right: self.right,
        })
    }
}

pub use proto::primitives::DecodedAdviceMapEntry as AdviceMapEntry;

impl Verify for AdviceMapEntry {
    type Verified = (miden_protocol::Word, alloc::vec::Vec<miden_protocol::Felt>);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((self.key, self.values))
    }
}

pub use proto::primitives::DecodedAdviceStack as AdviceStack;

impl Verify for AdviceStack {
    type Verified = miden_protocol::vm::AdviceStack;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(self.values.into_iter().collect())
    }
}

pub use proto::primitives::DecodedAdviceMap as AdviceMap;

impl Verify for AdviceMap {
    type Verified = miden_protocol::vm::AdviceMap;
    type Error = AdviceError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let mut entries = alloc::collections::BTreeMap::new();
        for entry in self.entries {
            if entries.insert(entry.key, entry.values).is_some() {
                return Err(AdviceError::DuplicateMapKey(entry.key));
            }
        }
        Ok(entries.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdviceError {
    #[error("duplicate advice map key {0}")]
    DuplicateMapKey(miden_protocol::Word),
    #[error("duplicate Merkle store parent {0}")]
    DuplicateMerkleParent(miden_protocol::Word),
}

pub use proto::primitives::DecodedMerkleStore as MerkleStore;

impl Verify for MerkleStore {
    type Verified = miden_protocol::crypto::merkle::store::MerkleStore;
    type Error = AdviceError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let mut nodes = alloc::collections::BTreeMap::new();
        for node in self.nodes {
            let node = unwrap_infallible(node.verify());
            if nodes.insert(node.value, node.clone()).is_some() {
                return Err(AdviceError::DuplicateMerkleParent(node.value));
            }
        }
        let mut store = Self::Verified::new();
        store.extend(nodes.into_values());
        Ok(store)
    }
}

pub use proto::primitives::DecodedAdviceInputs as AdviceInputs;

impl Verify for AdviceInputs {
    type Verified = miden_protocol::vm::AdviceInputs;
    type Error = AdviceError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            unwrap_infallible(self.advice_stack.verify()),
            self.advice_map.verify()?,
            self.merkle_store.verify()?,
        ))
    }
}
