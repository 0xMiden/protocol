use alloc::string::ToString;
use alloc::vec::Vec;

use super::{
    AccountError,
    AccountStorageDelta,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Felt,
    Serializable,
    Word,
};
use crate::account::AccountComponent;
use crate::crypto::SequentialCommit;

mod slot;
pub use slot::{StorageSlot, StorageSlotContent, StorageSlotId, StorageSlotName, StorageSlotType};

mod map;
pub use map::{PartialStorageMap, StorageMap, StorageMapWitness};

mod header;
pub use header::{AccountStorageHeader, StorageSlotHeader};

mod partial;
pub use partial::PartialStorage;

// ACCOUNT STORAGE
// ================================================================================================

/// Account storage is composed of a variable number of name-addressable [`StorageSlot`]s up to
/// 255 slots in total.
///
/// Each slot consists of a [`StorageSlotName`] and [`StorageSlotContent`] which defines its size
/// and structure. Currently, the following content types are supported:
/// - [`StorageSlotContent::Value`]: contains a single [`Word`] of data (i.e., 32 bytes).
/// - [`StorageSlotContent::Map`]: contains a [`StorageMap`] which is a key-value map where both
///   keys and values are [Word]s. The value of a storage slot containing a map is the commitment to
///   the underlying map.
///
/// Slots are sorted by [`StorageSlotName`] (or [`StorageSlotId`] equivalently). This order is
/// necessary to:
/// - Simplify lookups of slots in the transaction kernel (using `std::collections::sorted_array`
///   from the miden core library)
/// - Allow the [`AccountStorageDelta`] to work only with slot names instead of slot indices.
/// - Make it simple to check for duplicates by iterating the slots and checking that no two
///   adjacent items have the same slot name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountStorage {
    slots: Vec<StorageSlot>,
}

impl AccountStorage {
    /// The maximum number of storage slots allowed in an account storage.
    pub const MAX_NUM_STORAGE_SLOTS: usize = 255;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new instance of account storage initialized with the provided storage slots.
    ///
    /// This function sorts the slots by [`StorageSlotName`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of [`StorageSlot`]s exceeds 255.
    /// - There are multiple storage slots with the same [`StorageSlotName`].
    pub fn new(mut slots: Vec<StorageSlot>) -> Result<AccountStorage, AccountError> {
        let num_slots = slots.len();

        if num_slots > Self::MAX_NUM_STORAGE_SLOTS {
            return Err(AccountError::StorageTooManySlots(num_slots as u64));
        }

        // Unstable sort is fine because we require all names to be unique.
        slots.sort_unstable();

        // Check for slot name uniqueness by checking each neighboring slot's IDs. This is
        // sufficient because the slots are sorted.
        for slots in slots.windows(2) {
            if slots[0].id() == slots[1].id() {
                return Err(AccountError::DuplicateStorageSlotName(slots[0].name().clone()));
            }
        }

        Ok(Self { slots })
    }

    /// Creates an [`AccountStorage`] from the provided components' storage slots.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of [`StorageSlot`]s of all components exceeds 255.
    /// - There are multiple storage slots with the same [`StorageSlotName`].
    pub(super) fn from_components(
        components: Vec<AccountComponent>,
    ) -> Result<AccountStorage, AccountError> {
        let storage_slots = components
            .into_iter()
            .flat_map(|component| {
                let AccountComponent { storage_slots, .. } = component;
                storage_slots.into_iter()
            })
            .collect();

        Self::new(storage_slots)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Converts storage slots of this account storage into a vector of field elements.
    ///
    /// Each storage slot is represented by exactly 8 elements:
    ///
    /// ```text
    /// [[0, slot_type, slot_id_suffix, slot_id_prefix], SLOT_VALUE]
    /// ```
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns the commitment to the [`AccountStorage`].
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the number of slots in the account's storage.
    pub fn num_slots(&self) -> u8 {
        // SAFETY: The constructors of account storage ensure that the number of slots fits into a
        // u8.
        self.slots.len() as u8
    }

    /// Returns a reference to the storage slots.
    pub fn slots(&self) -> &[StorageSlot] {
        &self.slots
    }

    /// Consumes self and returns the storage slots of the account storage.
    pub fn into_slots(self) -> Vec<StorageSlot> {
        self.slots
    }

    /// Returns an [AccountStorageHeader] for this account storage.
    pub fn to_header(&self) -> AccountStorageHeader {
        AccountStorageHeader::new(self.slots.iter().map(StorageSlotHeader::from).collect())
            .expect("slots should be valid as ensured by AccountStorage")
    }

    /// Returns a reference to the storage slot with the provided name, if it exists, `None`
    /// otherwise.
    pub fn get(&self, slot_name: &StorageSlotName) -> Option<&StorageSlot> {
        self.slots.iter().find(|slot| slot.name().id() == slot_name.id())
    }

    /// Returns a mutable reference to the storage slot with the provided name, if it exists, `None`
    /// otherwise.
    fn get_mut(&mut self, slot_name: &StorageSlotName) -> Option<&mut StorageSlot> {
        self.slots.iter_mut().find(|slot| slot.name().id() == slot_name.id())
    }

    /// Returns an item from the storage slot with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A slot with the provided name does not exist.
    pub fn get_item(&self, slot_name: &StorageSlotName) -> Result<Word, AccountError> {
        self.get(slot_name)
            .map(|slot| slot.content().value())
            .ok_or_else(|| AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() })
    }

    /// Returns a map item from the map in the storage slot with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A slot with the provided name does not exist.
    /// - If the [`StorageSlot`] is not [`StorageSlotType::Map`].
    pub fn get_map_item(
        &self,
        slot_name: &StorageSlotName,
        key: Word,
    ) -> Result<Word, AccountError> {
        self.get(slot_name)
            .ok_or_else(|| AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() })
            .and_then(|slot| match slot.content() {
                StorageSlotContent::Map(map) => Ok(map.get(&key)),
                _ => Err(AccountError::StorageSlotNotMap(slot_name.clone())),
            })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Applies the provided delta to this account storage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The updates violate storage constraints.
    pub(super) fn apply_delta(&mut self, delta: &AccountStorageDelta) -> Result<(), AccountError> {
        // Update storage values
        for (slot_name, &value) in delta.values() {
            self.set_item(slot_name, value)?;
        }

        // Update storage maps
        for (slot_name, map_delta) in delta.maps() {
            let slot = self
                .get_mut(slot_name)
                .ok_or(AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() })?;

            let storage_map = match slot.content_mut() {
                StorageSlotContent::Map(map) => map,
                _ => return Err(AccountError::StorageSlotNotMap(slot_name.clone())),
            };

            storage_map.apply_delta(map_delta)?;
        }

        Ok(())
    }

    /// Updates the value of the storage slot with the given name.
    ///
    /// This method should be used only to update value slots. For updating values
    /// in storage maps, please see [`AccountStorage::set_map_item`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A slot with the provided name does not exist.
    /// - The [`StorageSlot`] is not [`StorageSlotType::Value`].
    pub fn set_item(
        &mut self,
        slot_name: &StorageSlotName,
        value: Word,
    ) -> Result<Word, AccountError> {
        let slot = self.get_mut(slot_name).ok_or_else(|| {
            AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() }
        })?;

        let StorageSlotContent::Value(old_value) = slot.content() else {
            return Err(AccountError::StorageSlotNotValue(slot_name.clone()));
        };
        let old_value = *old_value;

        let mut new_slot = StorageSlotContent::Value(value);
        core::mem::swap(slot.content_mut(), &mut new_slot);

        Ok(old_value)
    }

    /// Updates the value of a key-value pair of a storage map with the given name.
    ///
    /// This method should be used only to update storage maps. For updating values
    /// in storage slots, please see [AccountStorage::set_item()].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A slot with the provided name does not exist.
    /// - If the [`StorageSlot`] is not [`StorageSlotType::Map`].
    pub fn set_map_item(
        &mut self,
        slot_name: &StorageSlotName,
        raw_key: Word,
        value: Word,
    ) -> Result<(Word, Word), AccountError> {
        let slot = self.get_mut(slot_name).ok_or_else(|| {
            AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() }
        })?;

        let StorageSlotContent::Map(storage_map) = slot.content_mut() else {
            return Err(AccountError::StorageSlotNotMap(slot_name.clone()));
        };

        let old_root = storage_map.root();

        let old_value = storage_map.insert(raw_key, value)?;

        Ok((old_root, old_value))
    }
}

// ITERATORS
// ================================================================================================

impl IntoIterator for AccountStorage {
    type Item = StorageSlot;
    type IntoIter = alloc::vec::IntoIter<StorageSlot>;

    fn into_iter(self) -> Self::IntoIter {
        self.slots.into_iter()
    }
}

// SEQUENTIAL COMMIT
// ================================================================================================

impl SequentialCommit for AccountStorage {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        self.slots()
            .iter()
            .flat_map(|slot| {
                StorageSlotHeader::new(
                    slot.name().clone(),
                    slot.content().slot_type(),
                    slot.content().value(),
                )
                .to_elements()
            })
            .collect()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountStorage {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.slots().len() as u8);
        target.write_many(self.slots());
    }

    fn get_size_hint(&self) -> usize {
        // Size of the serialized slot length.
        let u8_size = 0u8.get_size_hint();
        let mut size = u8_size;

        for slot in self.slots() {
            size += slot.get_size_hint();
        }

        size
    }
}

impl Deserializable for AccountStorage {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_slots = source.read_u8()? as usize;
        let slots = source.read_many::<StorageSlot>(num_slots)?;

        Self::new(slots).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::{AccountStorage, Deserializable, Serializable};
    use crate::account::{AccountStorageHeader, StorageSlot, StorageSlotHeader, StorageSlotName};
    use crate::errors::AccountError;

    #[test]
    fn test_serde_account_storage() -> anyhow::Result<()> {
        // empty storage
        let storage = AccountStorage::new(vec![]).unwrap();
        let bytes = storage.to_bytes();
        assert_eq!(storage, AccountStorage::read_from_bytes(&bytes).unwrap());

        // storage with values for default types
        let storage = AccountStorage::new(vec![
            StorageSlot::with_empty_value(StorageSlotName::new("miden::test::value")?),
            StorageSlot::with_empty_map(StorageSlotName::new("miden::test::map")?),
        ])
        .unwrap();
        let bytes = storage.to_bytes();
        assert_eq!(storage, AccountStorage::read_from_bytes(&bytes).unwrap());

        Ok(())
    }

    #[test]
    fn test_get_slot_by_name() -> anyhow::Result<()> {
        let counter_slot = StorageSlotName::new("miden::test::counter")?;
        let map_slot = StorageSlotName::new("miden::test::map")?;

        let slots = vec![
            StorageSlot::with_empty_value(counter_slot.clone()),
            StorageSlot::with_empty_map(map_slot.clone()),
        ];
        let storage = AccountStorage::new(slots.clone())?;

        assert_eq!(storage.get(&counter_slot).unwrap(), &slots[0]);
        assert_eq!(storage.get(&map_slot).unwrap(), &slots[1]);

        Ok(())
    }

    #[test]
    fn test_account_storage_and_header_fail_on_duplicate_slot_name() -> anyhow::Result<()> {
        let slot_name0 = StorageSlotName::mock(0);
        let slot_name1 = StorageSlotName::mock(1);
        let slot_name2 = StorageSlotName::mock(2);

        let mut slots = vec![
            StorageSlot::with_empty_value(slot_name0.clone()),
            StorageSlot::with_empty_value(slot_name1.clone()),
            StorageSlot::with_empty_map(slot_name0.clone()),
            StorageSlot::with_empty_value(slot_name2.clone()),
        ];

        // Set up a test where the slots we pass are not already sorted
        // This ensures the duplicate is correctly found
        let err = AccountStorage::new(slots.clone()).unwrap_err();

        assert_matches!(err, AccountError::DuplicateStorageSlotName(name) => {
            assert_eq!(name, slot_name0);
        });

        slots.sort_unstable();
        let err = AccountStorageHeader::new(slots.iter().map(StorageSlotHeader::from).collect())
            .unwrap_err();

        assert_matches!(err, AccountError::DuplicateStorageSlotName(name) => {
            assert_eq!(name, slot_name0);
        });

        Ok(())
    }
}
