use alloc::string::String;

use miden_crypto::merkle::smt::{LeafIndex, SMT_DEPTH};
use miden_protocol_macros::WordWrapper;

use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
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
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The serialized size of the map key in bytes.
    pub const SERIALIZED_SIZE: usize = Word::SERIALIZED_SIZE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`StorageMapKey`] from the given word.
    pub fn new(word: Word) -> Self {
        Self::from_raw(word)
    }

    /// Returns the storage map key based on an empty word.
    pub fn empty() -> Self {
        Self::from_raw(Word::empty())
    }

    /// Creates a [`StorageMapKey`] from a `u32` index.
    ///
    /// This is a convenience constructor for the common pattern of using sequential indices
    /// as storage map keys, producing a key of `[idx, 0, 0, 0]`.
    pub fn from_index(idx: u32) -> Self {
        Self::from_raw(Word::from([idx, 0, 0, 0]))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

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

impl core::fmt::Display for StorageMapKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.as_word()))
    }
}

impl Serializable for StorageMapKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_many(self.as_word());
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for StorageMapKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let key = source.read()?;
        Ok(StorageMapKey::from_raw(key))
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
