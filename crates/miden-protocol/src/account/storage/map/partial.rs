use alloc::collections::BTreeMap;

use miden_core::utils::{Deserializable, Serializable};
use miden_crypto::Word;
use miden_crypto::merkle::smt::{LeafIndex, PartialSmt, SMT_DEPTH, SmtLeaf, SmtProof};
use miden_crypto::merkle::{InnerNodeInfo, MerkleError};

use crate::account::{StorageMap, StorageMapWitness};
use crate::utils::serde::{ByteReader, DeserializationError};

/// A partial representation of a [`StorageMap`], containing only proofs for a subset of the
/// key-value pairs.
///
/// A partial storage map carries only the Merkle authentication data a transaction will need.
/// Every included entry pairs a value with its proof, letting the transaction kernel verify reads
/// (and prepare writes) without needing the complete tree.
///
/// ## Guarantees
///
/// This type guarantees that the raw key-value pairs it contains are all present in the
/// contained partial SMT. Note that the inverse is not necessarily true. The SMT may contain more
/// entries than the map because to prove inclusion of a given raw key A an
/// [`SmtLeaf::Multiple`] may be present that contains both keys hash(A) and hash(B). However, B may
/// not be present in the key-value pairs and this is a valid state.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PartialStorageMap {
    partial_smt: PartialSmt,
    /// The entries of the map where the key is the raw user-chosen one.
    ///
    /// It is an invariant of this type that the map's entries are always consistent with the
    /// partial SMT's entries and vice-versa.
    entries: BTreeMap<Word, Word>,
}

impl PartialStorageMap {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [`PartialStorageMap`] from a [`StorageMap`] root.
    ///
    /// For conversion from a [`StorageMap`], prefer [`Self::new_minimal`] to be more explicit.
    pub fn new(root: Word) -> Self {
        PartialStorageMap {
            partial_smt: PartialSmt::new(root),
            entries: BTreeMap::new(),
        }
    }

    /// Returns a new instance of a [`PartialStorageMap`] with all provided witnesses added to it.
    pub fn with_witnesses(
        witnesses: impl IntoIterator<Item = StorageMapWitness>,
    ) -> Result<Self, MerkleError> {
        let mut map = BTreeMap::new();

        let partial_smt = PartialSmt::from_proofs(witnesses.into_iter().map(|witness| {
            map.extend(witness.entries());
            SmtProof::from(witness)
        }))?;

        Ok(PartialStorageMap { partial_smt, entries: map })
    }

    /// Converts a [`StorageMap`] into a partial storage representation.
    ///
    /// The resulting [`PartialStorageMap`] will contain the _full_ entries and merkle paths of the
    /// original storage map.
    pub fn new_full(storage_map: StorageMap) -> Self {
        let partial_smt = PartialSmt::from(storage_map.smt);
        let entries = storage_map.entries;

        PartialStorageMap { partial_smt, entries }
    }

    /// Converts a [`StorageMap`] into a partial storage representation.
    ///
    /// The resulting [`PartialStorageMap`] will represent the root of the storage map, but not
    /// track any key-value pairs, which means it is the most _minimal_ representation of the
    /// storage map.
    pub fn new_minimal(storage_map: &StorageMap) -> Self {
        Self::new(storage_map.root())
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the underlying [`PartialSmt`].
    pub fn partial_smt(&self) -> &PartialSmt {
        &self.partial_smt
    }

    /// Returns the root of the underlying [`PartialSmt`].
    pub fn root(&self) -> Word {
        self.partial_smt.root()
    }

    /// Looks up the provided key in this map and returns:
    /// - a non-empty [`Word`] if the key is tracked by this map and exists in it,
    /// - [`Word::empty`] if the key is tracked by this map and does not exist,
    /// - `None` if the key is not tracked by this map.
    pub fn get(&self, raw_key: &Word) -> Option<Word> {
        let hashed_key = StorageMap::hash_key(*raw_key);
        // This returns an error if the key is not tracked which we map to a `None`.
        self.partial_smt.get_value(&hashed_key).ok()
    }

    /// Returns an opening of the leaf associated with the raw key.
    ///
    /// Conceptually, an opening is a Merkle path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial storage map.
    pub fn open(&self, raw_key: &Word) -> Result<StorageMapWitness, MerkleError> {
        let hashed_key = StorageMap::hash_key(*raw_key);
        let smt_proof = self.partial_smt.open(&hashed_key)?;
        let value = self.entries.get(raw_key).copied().unwrap_or_default();

        // SAFETY: The key value pair is guaranteed to be present in the provided proof since we
        // open its hashed version and because of the guarantees of the partial storage map.
        Ok(StorageMapWitness::new_unchecked(smt_proof, [(*raw_key, value)]))
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of the underlying [`PartialSmt`].
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.partial_smt.leaves()
    }

    /// Returns an iterator over the key-value pairs in this storage map.
    ///
    /// Note that the returned key is the raw map key.
    pub fn entries(&self) -> impl Iterator<Item = (&Word, &Word)> {
        self.entries.iter()
    }

    /// Returns an iterator over the inner nodes of the underlying [`PartialSmt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.partial_smt.inner_nodes()
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a [`StorageMapWitness`] for the specific key-value pair to this [`PartialStorageMap`].
    pub fn add(&mut self, witness: StorageMapWitness) -> Result<(), MerkleError> {
        self.entries.extend(witness.entries().map(|(key, value)| (*key, *value)));
        self.partial_smt.add_proof(SmtProof::from(witness))
    }
}

impl Serializable for PartialStorageMap {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        target.write(&self.partial_smt);
        target.write_usize(self.entries.len());
        target.write_many(self.entries.keys());
    }
}

impl Deserializable for PartialStorageMap {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut map = BTreeMap::new();

        let partial_smt: PartialSmt = source.read()?;
        let num_entries: usize = source.read()?;

        for _ in 0..num_entries {
            let key: Word = source.read()?;
            let hashed_map_key = StorageMap::hash_key(key);
            let value = partial_smt.get_value(&hashed_map_key).map_err(|err| {
                DeserializationError::InvalidValue(format!(
                    "failed to find map key {key} in partial SMT: {err}"
                ))
            })?;
            map.insert(key, value);
        }

        Ok(PartialStorageMap { partial_smt, entries: map })
    }
}
