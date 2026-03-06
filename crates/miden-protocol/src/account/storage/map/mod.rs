use alloc::collections::BTreeMap;

use miden_core::EMPTY_WORD;
use miden_crypto::merkle::EmptySubtreeRoots;

use super::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, Word};
use crate::account::StorageMapDelta;
use crate::crypto::merkle::InnerNodeInfo;
use crate::crypto::merkle::smt::{LeafIndex, SMT_DEPTH, Smt, SmtLeaf};
use crate::errors::{AccountError, StorageMapError};

mod key;
pub use key::{StorageMapKey, StorageMapKeyHash};

mod partial;
pub use partial::PartialStorageMap;

mod witness;
pub use witness::StorageMapWitness;

// ACCOUNT STORAGE MAP
// ================================================================================================

/// Empty storage map root.
pub const EMPTY_STORAGE_MAP_ROOT: Word = *EmptySubtreeRoots::entry(StorageMap::DEPTH, 0);

/// An account storage map is a sparse merkle tree of depth [`Self::DEPTH`].
///
/// It can be used to store a large amount of data in an account than would be otherwise possible
/// using just the account's storage slots. This works by storing the root of the map's underlying
/// SMT in one account storage slot. Each map entry is a leaf in the tree and its inclusion is
/// proven while retrieving it (e.g. via `active_account::get_map_item`).
///
/// As a side-effect, this also means that _not all_ entries of the map have to be present at
/// transaction execution time in order to access or modify the map. It is sufficient if _just_ the
/// accessed/modified items are present in the advice provider.
///
/// Because the keys of the map are user-chosen and thus not necessarily uniformly distributed, the
/// tree could be imbalanced and made less efficient. To mitigate that, the keys used in the
/// storage map are hashed before they are inserted into the SMT, which creates a uniform
/// distribution. The original keys are retained in a separate map. This causes redundancy but
/// allows for introspection of the map, e.g. by querying the set of stored (original) keys which is
/// useful in debugging and explorer scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMap {
    /// The SMT where each key is the hashed original key.
    smt: Smt,
    /// The entries of the map that retains the original unhashed keys (i.e. [`StorageMapKey`]).
    ///
    /// It is an invariant of this type that the map's entries are always consistent with the SMT's
    /// entries and vice-versa.
    entries: BTreeMap<StorageMapKey, Word>,
}

impl StorageMap {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The depth of the SMT that represents the storage map.
    pub const DEPTH: u8 = SMT_DEPTH;

    /// The default value of empty leaves.
    pub const EMPTY_VALUE: Word = Smt::EMPTY_VALUE;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [StorageMap].
    ///
    /// All leaves in the returned tree are set to [Self::EMPTY_VALUE].
    pub fn new() -> Self {
        StorageMap {
            smt: Smt::new(),
            entries: BTreeMap::new(),
        }
    }

    /// Creates a new [`StorageMap`] from the provided key-value entries.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided entries contain multiple values for the same key.
    pub fn with_entries<I: ExactSizeIterator<Item = (StorageMapKey, Word)>>(
        entries: impl IntoIterator<Item = (StorageMapKey, Word), IntoIter = I>,
    ) -> Result<Self, StorageMapError> {
        let mut map = BTreeMap::new();

        for (key, value) in entries {
            if let Some(prev_value) = map.insert(key, value) {
                return Err(StorageMapError::DuplicateKey {
                    key,
                    value0: prev_value,
                    value1: value,
                });
            }
        }

        Ok(Self::from_btree_map(map))
    }

    /// Creates a new [`StorageMap`] from the given map. For internal use.
    fn from_btree_map(entries: BTreeMap<StorageMapKey, Word>) -> Self {
        let hashed_keys_iter = entries.iter().map(|(key, value)| (key.hash().as_word(), *value));
        let smt = Smt::with_entries(hashed_keys_iter)
            .expect("btree maps should not contain duplicate keys");

        StorageMap { smt, entries }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the underlying sparse merkle tree.
    pub fn root(&self) -> Word {
        self.smt.root()
    }

    /// Returns the number of non-empty leaves in this storage map.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.smt.num_leaves()
    }

    /// Returns the number of key-value pairs with non-default values in this storage map.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_entries(&self) -> usize {
        self.smt.num_entries()
    }

    /// Returns the value corresponding to the key or [`Self::EMPTY_VALUE`] if the key is not
    /// associated with a value.
    pub fn get(&self, key: &StorageMapKey) -> Word {
        self.entries.get(key).copied().unwrap_or_default()
    }

    /// Returns an opening of the leaf associated with the given key.
    ///
    /// Conceptually, an opening is a Merkle path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &StorageMapKey) -> StorageMapWitness {
        let smt_proof = self.smt.open(&key.hash().as_word());
        let value = self.entries.get(key).copied().unwrap_or_default();

        // SAFETY: The key value pair is guaranteed to be present in the provided proof since we
        // open its hashed version and because of the guarantees of the storage map.
        StorageMapWitness::new_unchecked(smt_proof, [(*key, value)])
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of the underlying [`Smt`].
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.smt.leaves() // Delegate to Smt's leaves method
    }

    /// Returns an iterator over the key-value pairs in this storage map.
    pub fn entries(&self) -> impl Iterator<Item = (&StorageMapKey, &Word)> {
        self.entries.iter()
    }

    /// Returns an iterator over the inner nodes of the underlying [`Smt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.smt.inner_nodes() // Delegate to Smt's inner_nodes method
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts or updates the given key value pair and returns the previous value, or
    /// [`Self::EMPTY_VALUE`] if no entry was previously present.
    ///
    /// If the provided `value` is [`Self::EMPTY_VALUE`] the entry will be removed.
    pub fn insert(&mut self, key: StorageMapKey, value: Word) -> Result<Word, AccountError> {
        if value == EMPTY_WORD {
            self.entries.remove(&key);
        } else {
            self.entries.insert(key, value);
        }

        let hashed_key = key.hash();
        self.smt
            .insert(hashed_key.into(), value)
            .map_err(AccountError::MaxNumStorageMapLeavesExceeded)
    }

    /// Applies the provided delta to this account storage.
    pub fn apply_delta(&mut self, delta: &StorageMapDelta) -> Result<Word, AccountError> {
        // apply the updated and cleared leaves to the storage map
        for (&key, &value) in delta.entries().iter() {
            self.insert(key.into_inner(), value)?;
        }

        Ok(self.root())
    }

    /// Consumes the map and returns the underlying map of entries.
    pub fn into_entries(self) -> BTreeMap<StorageMapKey, Word> {
        self.entries
    }
}

impl Default for StorageMap {
    fn default() -> Self {
        Self::new()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StorageMap {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.entries.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.smt.get_size_hint()
    }
}

impl Deserializable for StorageMap {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let map = BTreeMap::read_from(source)?;
        Ok(Self::from_btree_map(map))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::{
        Deserializable,
        EMPTY_STORAGE_MAP_ROOT,
        Serializable,
        StorageMap,
        StorageMapKey,
        Word,
    };
    use crate::errors::StorageMapError;

    #[test]
    fn account_storage_serialization() {
        // StorageMap for default types (empty map)
        let storage_map_default = StorageMap::default();
        let bytes = storage_map_default.to_bytes();
        assert_eq!(storage_map_default, StorageMap::read_from_bytes(&bytes).unwrap());

        // StorageMap with values
        let storage_map_leaves_2 = [
            (StorageMapKey::from_array([101, 102, 103, 104]), Word::from([1, 2, 3, 4u32])),
            (StorageMapKey::from_array([105, 106, 107, 108]), Word::from([5, 6, 7, 8u32])),
        ];
        let storage_map = StorageMap::with_entries(storage_map_leaves_2).unwrap();
        assert_eq!(storage_map.num_entries(), 2);
        assert_eq!(storage_map.num_leaves(), 2);

        let bytes = storage_map.to_bytes();
        let deserialized_map = StorageMap::read_from_bytes(&bytes).unwrap();

        assert_eq!(storage_map.root(), deserialized_map.root());

        assert_eq!(storage_map, deserialized_map);
    }

    #[test]
    fn test_empty_storage_map_constants() {
        // If these values don't match, update the constants.
        assert_eq!(StorageMap::default().root(), EMPTY_STORAGE_MAP_ROOT);
    }

    #[test]
    fn account_storage_map_fails_on_duplicate_entries() {
        // StorageMap with values
        let storage_map_leaves_2 = [
            (StorageMapKey::from_array([101, 102, 103, 104]), Word::from([1, 2, 3, 4u32])),
            (StorageMapKey::from_array([101, 102, 103, 104]), Word::from([5, 6, 7, 8u32])),
        ];

        let error = StorageMap::with_entries(storage_map_leaves_2).unwrap_err();
        assert_matches!(error, StorageMapError::DuplicateKey { .. });
    }
}
