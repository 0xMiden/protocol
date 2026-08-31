use alloc::collections::BTreeMap;

use miden_crypto::Word;
use miden_crypto::merkle::smt::{LeafIndex, PartialSmt, SMT_DEPTH, SmtLeaf, SmtProof};
use miden_crypto::merkle::{InnerNodeInfo, MerkleError};

use crate::account::{StorageMap, StorageMapKey, StorageMapWitness};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

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
    /// The entries of the map that retains the original unhashed keys (i.e. [`StorageMapKey`]).
    ///
    /// It is an invariant of this type that the map's entries are always consistent with the
    /// partial SMT's entries and vice-versa.
    entries: BTreeMap<StorageMapKey, Word>,
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

    /// Creates a [`PartialStorageMap`] from a [`PartialSmt`] and the raw keys whose values are
    /// looked up from the SMT.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a key is supplied more than once.
    /// - a key's hashed form is not tracked by the partial SMT.
    pub fn try_from_parts(
        partial_smt: PartialSmt,
        keys: impl IntoIterator<Item = StorageMapKey>,
    ) -> Result<Self, MerkleError> {
        let mut entries = BTreeMap::new();

        for key in keys {
            if entries.contains_key(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(
                    key.hash().to_leaf_index().position(),
                ));
            }

            let value = partial_smt.get_value(&key.hash().as_word())?;
            entries.insert(key, value);
        }

        Ok(Self { partial_smt, entries })
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
    pub fn get(&self, key: &StorageMapKey) -> Option<Word> {
        let hash_word = key.hash().as_word();
        // This returns an error if the key is not tracked which we map to a `None`.
        self.partial_smt.get_value(&hash_word).ok()
    }

    /// Returns an opening of the leaf associated with the given key.
    ///
    /// Conceptually, an opening is a Merkle path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial storage map.
    pub fn open(&self, key: &StorageMapKey) -> Result<StorageMapWitness, MerkleError> {
        let smt_proof = self.partial_smt.open(&key.hash().as_word())?;
        let value = self.entries.get(key).copied().unwrap_or_default();

        // SAFETY: The key value pair is guaranteed to be present in the provided proof since we
        // open its hashed version and because of the guarantees of the partial storage map.
        Ok(StorageMapWitness::new_unchecked(smt_proof, [(*key, value)]))
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of the underlying [`PartialSmt`].
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.partial_smt.leaves()
    }

    /// Returns an iterator over the key-value pairs in this storage map.
    pub fn entries(&self) -> impl Iterator<Item = (&StorageMapKey, &Word)> {
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
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.partial_smt);
        target.write_usize(self.entries.len());
        target.write_many(self.entries.keys());
    }
}

impl Deserializable for PartialStorageMap {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let partial_smt: PartialSmt = source.read()?;
        let num_entries: usize = source.read()?;
        let keys = source
            .read_many_iter::<StorageMapKey>(num_entries)?
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;

        Self::try_from_parts(partial_smt, keys).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "failed to construct partial storage map from supplied keys: {err}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_crypto::merkle::MerkleError;
    use miden_crypto::merkle::smt::PartialSmt;

    use super::PartialStorageMap;
    use crate::Word;
    use crate::account::{StorageMap, StorageMapKey};

    #[test]
    fn try_from_parts_preserves_unrelated_partial_smt_material() -> anyhow::Result<()> {
        let tracked_key = StorageMapKey::from_index(1);
        let extra_key = StorageMapKey::from_index(2);
        let tracked_value = Word::from([1_u32, 0, 0, 0]);
        let extra_value = Word::from([2_u32, 0, 0, 0]);
        let storage_map = StorageMap::with_entries(
            [(tracked_key, tracked_value), (extra_key, extra_value)].into_iter(),
        )?;
        let partial_smt = PartialSmt::from_proofs([
            storage_map.open(&tracked_key).into(),
            storage_map.open(&extra_key).into(),
        ])?;

        let partial_map = PartialStorageMap::try_from_parts(partial_smt, [tracked_key])?;

        assert_eq!(partial_map.entries().collect::<Vec<_>>(), [(&tracked_key, &tracked_value)]);
        assert_eq!(partial_map.get(&extra_key), Some(extra_value));

        Ok(())
    }

    #[test]
    fn try_from_parts_rejects_duplicate_keys() -> anyhow::Result<()> {
        let key = StorageMapKey::from_index(1);
        let storage_map =
            StorageMap::with_entries([(key, Word::from([1_u32, 0, 0, 0]))].into_iter())?;
        let partial_smt = PartialSmt::from_proofs([storage_map.open(&key).into()])?;

        let result = PartialStorageMap::try_from_parts(partial_smt, [key, key]);

        assert_matches!(
            result,
            Err(MerkleError::DuplicateValuesForIndex(position))
                if position == key.hash().to_leaf_index().position()
        );

        Ok(())
    }

    #[test]
    fn try_from_parts_rejects_untracked_keys() {
        let key = StorageMapKey::from_index(1);
        let result = PartialStorageMap::try_from_parts(PartialSmt::new(Word::empty()), [key]);

        assert_matches!(
            result,
            Err(MerkleError::UntrackedKey(hashed_key)) if hashed_key == key.hash().as_word()
        );
    }
}
