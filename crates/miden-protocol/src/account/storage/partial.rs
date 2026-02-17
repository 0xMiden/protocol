use alloc::collections::{BTreeMap, BTreeSet};

use miden_core::utils::{Deserializable, Serializable};
use miden_crypto::Word;
use miden_crypto::merkle::InnerNodeInfo;
use miden_crypto::merkle::smt::SmtLeaf;

use super::{AccountStorage, AccountStorageHeader, StorageSlotContent};
use crate::account::PartialStorageMap;
use crate::errors::AccountError;

/// A partial representation of an account storage, containing only a subset of the storage data.
///
/// Partial storage is used to provide verifiable access to specific segments of account storage
/// without the need to provide the full storage data. It contains all needed parts for loading
/// account storage data into the transaction kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialStorage {
    /// Commitment of the account's storage slots.
    commitment: Word,
    /// Account storage header.
    header: AccountStorageHeader,
    /// Storage partial storage maps indexed by their root, containing a subset of the elements
    /// from the complete storage map.
    maps: BTreeMap<Word, PartialStorageMap>,
}

impl PartialStorage {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new instance of partial storage with the specified header and storage map SMTs.
    ///
    /// The storage commitment is computed during instantiation based on the provided header.
    /// Additionally, this function validates that the passed SMTs correspond to one of the map
    /// roots in the storage header.
    pub fn new(
        storage_header: AccountStorageHeader,
        storage_maps: impl IntoIterator<Item = PartialStorageMap>,
    ) -> Result<Self, AccountError> {
        let storage_map_roots: BTreeSet<_> = storage_header.map_slot_roots().collect();
        let mut maps = BTreeMap::new();
        for smt in storage_maps {
            // Check that the passed storage map partial SMT has a matching map slot root
            if !storage_map_roots.contains(&smt.root()) {
                return Err(AccountError::StorageMapRootNotFound(smt.root()));
            }
            maps.insert(smt.root(), smt);
        }

        let commitment = storage_header.to_commitment();
        Ok(Self { commitment, header: storage_header, maps })
    }

    /// Converts an [`AccountStorage`] into a partial storage representation.
    ///
    /// This creates a partial storage that contains the _full_ proofs for all key-value pairs
    /// in all map slots of the account storage.
    pub fn new_full(account_storage: AccountStorage) -> Self {
        let header: AccountStorageHeader = account_storage.to_header();
        let commitment = header.to_commitment();

        let mut maps = BTreeMap::new();
        for slot in account_storage {
            if let StorageSlotContent::Map(storage_map) = slot.into_parts().1 {
                let partial_map = PartialStorageMap::new_full(storage_map);
                maps.insert(partial_map.root(), partial_map);
            }
        }

        PartialStorage { header, maps, commitment }
    }

    /// Converts an [`AccountStorage`] into a partial storage representation.
    ///
    /// For every storage map, a single unspecified key-value pair is tracked so that the
    /// [`PartialStorageMap`] represents the correct root.
    pub fn new_minimal(account_storage: &AccountStorage) -> Self {
        let header: AccountStorageHeader = account_storage.to_header();
        let commitment = header.to_commitment();

        let mut maps = BTreeMap::new();
        for slot in account_storage.slots() {
            if let StorageSlotContent::Map(storage_map) = slot.content() {
                let partial_map = PartialStorageMap::new_minimal(storage_map);
                maps.insert(partial_map.root(), partial_map);
            }
        }

        PartialStorage { header, maps, commitment }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the header of this partial storage.
    pub fn header(&self) -> &AccountStorageHeader {
        &self.header
    }

    /// Returns the commitment of this partial storage.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    // TODO: Consider removing once no longer needed so we don't commit to the underlying BTreeMap
    // type.
    /// Consumes self and returns the underlying parts.
    pub fn into_parts(self) -> (Word, AccountStorageHeader, BTreeMap<Word, PartialStorageMap>) {
        (self.commitment, self.header, self.maps)
    }

    // TODO: Add from account storage with (slot/[key])?

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over inner nodes of all storage map proofs contained in this
    /// partial storage.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> {
        self.maps.iter().flat_map(|(_, map)| map.inner_nodes())
    }

    /// Iterator over every [`PartialStorageMap`] in this partial storage.
    pub fn maps(&self) -> impl Iterator<Item = &PartialStorageMap> + '_ {
        self.maps.values()
    }

    /// Iterator over all tracked, non‑empty leaves across every map.
    pub fn leaves(&self) -> impl Iterator<Item = &SmtLeaf> + '_ {
        self.maps().flat_map(|map| map.leaves()).map(|(_, leaf)| leaf)
    }
}

impl Serializable for PartialStorage {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        target.write(&self.header);
        target.write(&self.maps);
    }
}

impl Deserializable for PartialStorage {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_processor::DeserializationError> {
        let header: AccountStorageHeader = source.read()?;
        let map_smts: BTreeMap<Word, PartialStorageMap> = source.read()?;

        let commitment = header.to_commitment();

        Ok(PartialStorage { header, maps: map_smts, commitment })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use miden_core::Word;

    use crate::account::{
        AccountStorage,
        AccountStorageHeader,
        PartialStorage,
        PartialStorageMap,
        StorageMap,
        StorageSlot,
        StorageSlotName,
    };

    #[test]
    pub fn new_partial_storage() -> anyhow::Result<()> {
        let map_key_present: Word = [1u64, 2, 3, 4].try_into()?;
        let map_key_absent: Word = [9u64, 12, 18, 3].try_into()?;

        let mut map_1 = StorageMap::new();
        map_1.insert(map_key_absent, Word::try_from([1u64, 2, 3, 2])?).unwrap();
        map_1.insert(map_key_present, Word::try_from([5u64, 4, 3, 2])?).unwrap();
        assert_eq!(map_1.get(&map_key_present), [5u64, 4, 3, 2].try_into()?);

        let slot_name = StorageSlotName::new("miden::test_map")?;

        let storage =
            AccountStorage::new(vec![StorageSlot::with_map(slot_name.clone(), map_1.clone())])
                .unwrap();

        // Create partial storage with validation of one map key
        let storage_header = AccountStorageHeader::from(&storage);
        let witness = map_1.open(&map_key_present);

        let partial_storage =
            PartialStorage::new(storage_header, [PartialStorageMap::with_witnesses([witness])?])
                .context("creating partial storage")?;

        let slot_header = partial_storage.header.find_slot_header_by_name(&slot_name).unwrap();
        let retrieved_map = partial_storage.maps.get(&slot_header.value()).unwrap();
        assert!(retrieved_map.open(&map_key_absent).is_err());
        assert!(retrieved_map.open(&map_key_present).is_ok());
        Ok(())
    }
}
