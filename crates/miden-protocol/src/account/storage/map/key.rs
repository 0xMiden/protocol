use alloc::string::String;

use miden_crypto::merkle::smt::{LeafIndex, SMT_DEPTH};
use miden_protocol_macros::WordWrapper;

use crate::{Felt, Hasher, Word};

// STORAGE MAP KEY
// ================================================================================================

/// A raw, user-chosen key for a [`StorageMap`](super::StorageMap).
///
/// Storage map keys are user-chosen and thus not necessarily uniformly distributed. To mitigate
/// potential tree imbalance, keys are hashed before being inserted into the underlying SMT.
///
/// Use [`StorageMapKey::hash`] to produce the corresponding [`StorageMapKeyHash`] that is used
/// in the SMT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, WordWrapper)]
pub struct StorageMapKey(Word);

impl StorageMapKey {
    /// Hashes this raw map key to produce a [`StorageMapKeyHash`].
    ///
    /// Storage map keys are hashed before being inserted into the SMT to ensure a uniform
    /// key distribution.
    pub fn hash(&self) -> StorageMapKeyHash {
        StorageMapKeyHash::from_raw(Hasher::hash_elements(self.0.as_elements()))
    }
}

impl From<StorageMapKey> for Word {
    fn from(key: StorageMapKey) -> Self {
        key.0
    }
}

// STORAGE MAP KEY HASH
// ================================================================================================

/// A hashed key for a [`StorageMap`](super::StorageMap).
///
/// This is produced by hashing a [`StorageMapKey`] and is used as the actual key in the
/// underlying SMT. Wrapping the hashed key in a distinct type prevents accidentally using a raw
/// key where a hashed key is expected and vice-versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, WordWrapper)]
pub struct StorageMapKeyHash(Word);

impl StorageMapKeyHash {
    /// Returns the leaf index in the SMT for this hashed key.
    pub fn to_leaf_index(&self) -> LeafIndex<SMT_DEPTH> {
        self.0.into()
    }
}

impl From<StorageMapKeyHash> for Word {
    fn from(key: StorageMapKeyHash) -> Self {
        key.0
    }
}

impl From<StorageMapKey> for StorageMapKeyHash {
    fn from(key: StorageMapKey) -> Self {
        key.hash()
    }
}
