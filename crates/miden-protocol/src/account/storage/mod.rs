use alloc::string::ToString;
use alloc::vec::Vec;

use super::{
    AccountError,
    AccountStoragePatch,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Felt,
    Serializable,
    Word,
};
use crate::DoubleWord;
use crate::account::{
    AccountComponent,
    StorageArrayPatch,
    StorageMapPatch,
    StorageSlotPatch,
    StorageValuePatch,
};
use crate::asset::AssetCallbacks;
use crate::crypto::SequentialCommit;

pub(crate) mod slot;
pub use slot::{StorageSlot, StorageSlotContent, StorageSlotId, StorageSlotName, StorageSlotType};

mod array;
pub use array::{StorageArray, StorageArrayError, StorageArrayLength};

mod map;
pub use map::{PartialStorageMap, StorageMap, StorageMapKey, StorageMapKeyHash, StorageMapWitness};

mod header;
pub use header::{AccountStorageHeader, StorageSlotHeader, StorageSlotHeaderContent};

mod partial;
pub use partial::PartialStorage;

// ACCOUNT STORAGE
// ================================================================================================

/// Up to 255 named [`StorageSlot`]s, sorted by [`StorageSlotId`].
///
/// Slots contain a [`Word`], [`StorageArray`], or [`StorageMap`]. Payload is limited to
/// [`Self::MAX_NUM_STORAGE_WORDS`] words: values and map roots count as one word each, and arrays
/// count as their full length.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountStorage {
    slots: Vec<StorageSlot>,
}

impl AccountStorage {
    /// The maximum number of storage slots allowed in an account storage.
    pub const MAX_NUM_STORAGE_SLOTS: usize = 255;

    /// Maximum payload in words, counting values, map roots, and array contents.
    pub const MAX_NUM_STORAGE_WORDS: usize = 256;

    pub(crate) fn validate_payload_size(
        types: impl Iterator<Item = StorageSlotType>,
    ) -> Result<(), AccountError> {
        let num_words: usize = types.map(|slot_type| slot_type.num_words()).sum();
        if num_words > Self::MAX_NUM_STORAGE_WORDS {
            return Err(AccountError::StoragePayloadTooLarge(num_words));
        }
        Ok(())
    }

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
    /// - The total logical payload exceeds [`Self::MAX_NUM_STORAGE_WORDS`].
    /// - There are multiple storage slots with the same [`StorageSlotName`].
    pub fn new(mut slots: Vec<StorageSlot>) -> Result<AccountStorage, AccountError> {
        let num_slots = slots.len();

        if num_slots > Self::MAX_NUM_STORAGE_SLOTS {
            return Err(AccountError::StorageTooManySlots(num_slots as u64));
        }

        // Unstable sort is fine because we require all names to be unique.
        slots.sort_unstable_by(|a, b| a.name().cmp(b.name()));

        // Check for slot name uniqueness by checking each neighboring slot's IDs. This is
        // sufficient because the slots are sorted.
        for slots in slots.windows(2) {
            if slots[0].id() == slots[1].id() {
                return Err(AccountError::DuplicateStorageSlotName(slots[0].name().clone()));
            }
        }

        Self::validate_payload_size(slots.iter().map(StorageSlot::slot_type))?;
        Ok(Self { slots })
    }

    /// Creates an [`AccountStorage`] from the provided components' storage slots.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of [`StorageSlot`]s of all components exceeds 255.
    /// - The total payload exceeds [`Self::MAX_NUM_STORAGE_WORDS`].
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

    /// Returns `true` if the storage contains at least one of the protocol-reserved asset callback
    /// slots, `false` otherwise.
    ///
    /// Only the presence of a callback slot is relevant, not its value: a slot's value can be
    /// rewritten over the account's lifetime, while its presence can only change through an account
    /// upgrade, so only the presence can be tied to the immutable
    /// [`AssetCallbackFlag`](crate::account::AssetCallbackFlag) encoded in the account ID. See the
    /// [`AccountBuilder`](crate::account::AccountBuilder#asset-callbacks) docs for details.
    pub fn has_callback_slots(&self) -> bool {
        AssetCallbacks::slot_names()
            .iter()
            .any(|slot_name| self.get(slot_name).is_some())
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
        key: StorageMapKey,
    ) -> Result<Word, AccountError> {
        self.get(slot_name)
            .ok_or_else(|| AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() })
            .and_then(|slot| match slot.content() {
                StorageSlotContent::Map(map) => Ok(map.get(&key)),
                _ => Err(AccountError::StorageSlotNotMap(slot_name.clone())),
            })
    }

    /// Returns the full array in the named slot.
    ///
    /// # Errors
    ///
    /// Returns an error if the slot does not exist or is not an array.
    pub fn get_array(&self, slot_name: &StorageSlotName) -> Result<&StorageArray, AccountError> {
        let slot = self.get(slot_name).ok_or_else(|| AccountError::StorageSlotNameNotFound {
            slot_name: slot_name.clone(),
        })?;
        match slot.content() {
            StorageSlotContent::Array(array) => Ok(array),
            _ => Err(AccountError::StorageSlotNotArray(slot_name.clone())),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Applies the provided patch to this account storage.
    ///
    /// The final storage layout must satisfy the slot and word limits. If validation fails,
    /// storage is left unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The updates violate storage constraints.
    pub(super) fn apply_patch(&mut self, patch: &AccountStoragePatch) -> Result<(), AccountError> {
        if patch.is_empty() {
            return Ok(());
        }
        // Check the final layout before preparing changes. Map entries do not affect these limits.
        let retained = self.slots.iter().filter(|slot| patch.get(slot.name()).is_none());
        let replacements = || patch.slots().filter(|(_, patch)| !patch.patch_op().is_remove());
        let num_slots = retained.clone().count() + replacements().count();
        if num_slots > Self::MAX_NUM_STORAGE_SLOTS {
            return Err(AccountError::StorageTooManySlots(num_slots as u64));
        }
        Self::validate_payload_size(
            retained
                .map(StorageSlot::slot_type)
                .chain(replacements().map(|(_, patch)| patch.slot_type())),
        )?;

        let mut slots = Vec::new();
        let mut maps = Vec::new();
        for (name, slot_patch) in patch.slots() {
            let existing = self.get(name);
            if !slot_patch.patch_op().is_create() && existing.is_none() {
                return Err(AccountError::StorageSlotNameNotFound { slot_name: name.clone() });
            }
            let content = match slot_patch {
                StorageSlotPatch::Value(StorageValuePatch::Create { value }) => {
                    Some(StorageSlotContent::Value(*value))
                },
                StorageSlotPatch::Value(StorageValuePatch::Update { value }) => {
                    if !matches!(
                        existing.map(StorageSlot::content),
                        Some(StorageSlotContent::Value(_))
                    ) {
                        return Err(AccountError::StorageSlotNotValue(name.clone()));
                    }
                    Some(StorageSlotContent::Value(*value))
                },
                StorageSlotPatch::Map(StorageMapPatch::Create { entries }) => {
                    let map = StorageMap::from_btree_map(entries.as_map().clone())
                        .map_err(AccountError::MaxNumStorageMapLeavesExceeded)?;
                    Some(StorageSlotContent::Map(map))
                },
                StorageSlotPatch::Map(StorageMapPatch::Update { entries }) => {
                    let Some(StorageSlotContent::Map(map)) = existing.map(StorageSlot::content)
                    else {
                        return Err(AccountError::StorageSlotNotMap(name.clone()));
                    };
                    maps.push((name, entries, map.compute_mutations(entries)?));
                    continue;
                },
                StorageSlotPatch::Array(StorageArrayPatch::Create { array }) => {
                    Some(StorageSlotContent::Array(array.clone()))
                },
                StorageSlotPatch::Array(StorageArrayPatch::Update { entries }) => {
                    Some(StorageSlotContent::Array(entries.apply(self.get_array(name)?)?))
                },
                StorageSlotPatch::Array(StorageArrayPatch::Remove { length }) => {
                    let current = self.get_array(name)?.length();
                    if current != *length {
                        return Err(StorageArrayError::LengthMismatch {
                            expected: current.as_u16(),
                            actual: length.as_u16(),
                        }
                        .into());
                    }
                    None
                },
                StorageSlotPatch::Value(StorageValuePatch::Remove)
                | StorageSlotPatch::Map(StorageMapPatch::Remove) => None,
            };
            slots.push((name, content));
        }

        // All fallible work is complete. Map mutations contain only changed entries and nodes.
        for (name, entries, mutations) in maps {
            let slot = self.get_mut(name).expect("validated map slot");
            let StorageSlotContent::Map(map) = slot.content_mut() else {
                unreachable!("validated map slot");
            };
            map.apply_mutations(entries, mutations);
        }
        for (name, content) in slots {
            match content {
                Some(content) => self.create_slot(StorageSlot::new(name.clone(), content)),
                None => self.remove_slot(name).expect("validated storage slot"),
            }
        }
        Ok(())
    }

    /// Replaces an array's words, preserving its fixed length, and returns the previous array.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The slot does not exist or is not an array.
    /// - The new array has a different length.
    pub fn set_array(
        &mut self,
        slot_name: &StorageSlotName,
        array: StorageArray,
    ) -> Result<StorageArray, AccountError> {
        let slot = self.get_mut(slot_name).ok_or_else(|| {
            AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() }
        })?;
        let StorageSlotContent::Array(current) = slot.content_mut() else {
            return Err(AccountError::StorageSlotNotArray(slot_name.clone()));
        };
        if current.length() != array.length() {
            return Err(StorageArrayError::LengthMismatch {
                expected: current.length().as_u16(),
                actual: array.length().as_u16(),
            }
            .into());
        }
        Ok(core::mem::replace(current, array))
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
        key: StorageMapKey,
        value: Word,
    ) -> Result<(Word, Word), AccountError> {
        let slot = self.get_mut(slot_name).ok_or_else(|| {
            AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() }
        })?;

        let StorageSlotContent::Map(storage_map) = slot.content_mut() else {
            return Err(AccountError::StorageSlotNotMap(slot_name.clone()));
        };

        let old_root = storage_map.root();

        let old_value = storage_map.insert(key, value)?;

        Ok((old_root, old_value))
    }

    /// Removes the storage slot with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if a slot with the provided name does not exist.
    fn remove_slot(&mut self, slot_name: &StorageSlotName) -> Result<(), AccountError> {
        match self.slots.iter().position(|slot| slot.name().id() == slot_name.id()) {
            Some(index) => {
                self.slots.remove(index);
                Ok(())
            },
            None => Err(AccountError::StorageSlotNameNotFound { slot_name: slot_name.clone() }),
        }
    }

    /// Creates or replaces a slot in ID order. `apply_patch` checks the final storage limits.
    fn create_slot(&mut self, slot: StorageSlot) {
        match self.slots.binary_search_by(|existing| existing.name().cmp(slot.name())) {
            Ok(index) => self.slots[index] = slot,
            Err(index) => self.slots.insert(index, slot),
        }
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
                let id = slot.id();
                let header_word =
                    Word::new([Felt::ZERO, slot.slot_type().as_felt(), id.suffix(), id.prefix()]);
                DoubleWord::new(header_word, slot.value())
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
        let slots = source.read_many_iter::<StorageSlot>(num_slots)?.collect::<Result<_, _>>()?;

        Self::new(slots).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;

    use super::{AccountStorage, Deserializable, Serializable};
    use crate::Word;
    use crate::account::{
        AccountStorageHeader,
        AccountStoragePatch,
        StorageArray,
        StorageArrayLength,
        StorageArrayPatch,
        StorageArrayPatchEntries,
        StorageMap,
        StorageMapKey,
        StorageMapPatch,
        StorageMapPatchEntries,
        StorageSlot,
        StorageSlotHeader,
        StorageSlotName,
        StorageSlotPatch,
        StorageValuePatch,
    };
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

        slots.sort_unstable_by(|a, b| a.name().cmp(b.name()));
        let err = AccountStorageHeader::new(slots.iter().map(StorageSlotHeader::from).collect())
            .unwrap_err();

        assert_matches!(err, AccountError::DuplicateStorageSlotName(name) => {
            assert_eq!(name, slot_name0);
        });

        Ok(())
    }

    #[test]
    fn create_value_slot_recreates_existing() -> anyhow::Result<()> {
        let slot_name = StorageSlotName::mock(4);
        let mut storage = AccountStorage::new(vec![StorageSlot::with_value(
            slot_name.clone(),
            Word::from([1u32, 2, 3, 4]),
        )])?;

        // Creating a slot that already exists re-creates it, replacing the previous value.
        let new_value = Word::from([5u32, 6, 7, 8]);
        storage.create_slot(StorageSlot::with_value(slot_name.clone(), new_value));

        assert_eq!(storage.num_slots(), 1);
        assert_eq!(storage.get_item(&slot_name)?, new_value);

        Ok(())
    }

    #[test]
    fn remove_slot_rejects_absent() -> anyhow::Result<()> {
        let absent = StorageSlotName::new("miden::test::absent")?;
        let mut storage = AccountStorage::default();

        let err = storage.remove_slot(&absent).unwrap_err();
        assert_matches!(err, AccountError::StorageSlotNameNotFound { slot_name } => {
            assert_eq!(slot_name, absent);
        });

        Ok(())
    }

    #[test]
    fn create_and_remove_value_slot_roundtrip() -> anyhow::Result<()> {
        // Setup slot names so that the created slot is in the middle.
        let existing0 = StorageSlotName::mock(1);
        let existing1 = StorageSlotName::mock(7);
        let created = StorageSlotName::mock(20);
        assert!(existing0 < created);
        assert!(created < existing1);

        let value = Word::from([9u32, 8, 7, 6]);

        let mut storage = AccountStorage::new(vec![
            StorageSlot::with_value(existing0.clone(), value),
            StorageSlot::with_value(existing1.clone(), value),
        ])?;

        storage.create_slot(StorageSlot::with_value(created.clone(), value));
        assert_eq!(storage.num_slots(), 3);
        assert_eq!(storage.get_item(&created)?, value);
        assert!(
            storage.slots().is_sorted_by_key(|slot| slot.name()),
            "slots should remain sorted after insertion"
        );

        assert_eq!(storage.get_item(&existing0)?, value, "existing slot should remain accessible");
        assert_eq!(storage.get_item(&existing1)?, value, "existing slot should remain accessible");

        storage.remove_slot(&created)?;
        assert_eq!(storage.num_slots(), 2);
        assert_matches!(
            storage.get_item(&created).unwrap_err(),
            AccountError::StorageSlotNameNotFound { .. }
        );

        Ok(())
    }

    #[test]
    fn apply_storage_patch() -> anyhow::Result<()> {
        let updated = StorageSlotName::mock(1);
        let created = StorageSlotName::mock(2);
        let removed = StorageSlotName::mock(3);
        let map_name = StorageSlotName::mock(4);

        let init_value = Word::from([1u32, 2, 3, 4]);
        let final_value = Word::from([6u32, 7, 8, 9]);

        let mut storage = AccountStorage::new(vec![
            StorageSlot::with_value(updated.clone(), init_value),
            StorageSlot::with_value(removed.clone(), init_value),
            StorageSlot::with_map(
                map_name.clone(),
                StorageMap::with_entries(
                    (0..3).map(|i| (StorageMapKey::from_index(i), init_value)),
                )?,
            ),
        ])?;

        let patches = BTreeMap::from_iter([
            (
                created.clone(),
                StorageSlotPatch::Value(StorageValuePatch::Create { value: final_value }),
            ),
            (
                updated.clone(),
                StorageSlotPatch::Value(StorageValuePatch::Update { value: final_value }),
            ),
            (removed.clone(), StorageSlotPatch::Value(StorageValuePatch::Remove)),
            (
                map_name.clone(),
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_raw(BTreeMap::from([
                        (StorageMapKey::from_index(0), final_value),
                        (StorageMapKey::from_index(1), Word::empty()),
                        (StorageMapKey::from_index(3), final_value),
                    ])),
                }),
            ),
        ]);
        let patch = AccountStoragePatch::from_raw(patches)?;

        storage.apply_patch(&patch)?;

        assert_eq!(storage.num_slots(), 3);
        assert_eq!(storage.get_item(&created)?, final_value);
        assert_eq!(storage.get_item(&updated)?, final_value);
        assert_eq!(storage.get(&removed), None);
        let expected_map = StorageMap::with_entries([
            (StorageMapKey::from_index(0), final_value),
            (StorageMapKey::from_index(2), init_value),
            (StorageMapKey::from_index(3), final_value),
        ])?;
        assert_eq!(
            storage.get(&map_name),
            Some(&StorageSlot::with_map(map_name.clone(), expected_map))
        );

        Ok(())
    }

    #[test]
    fn rejected_storage_patch_preserves_maps() -> anyhow::Result<()> {
        let mut names = [StorageSlotName::mock(0), StorageSlotName::mock(1)];
        names.sort();
        let [map_name, array_name] = names;
        let key = StorageMapKey::from_index(0);
        let initial = AccountStorage::new(vec![
            StorageSlot::with_map(
                map_name.clone(),
                StorageMap::with_entries([(key, Word::from([1u32; 4]))])?,
            ),
            StorageSlot::with_array(
                array_name.clone(),
                StorageArray::empty(StorageArrayLength::try_from(255)?),
            ),
        ])?;
        let map_update = StorageSlotPatch::Map(StorageMapPatch::Update {
            entries: StorageMapPatchEntries::from_raw(BTreeMap::from([(key, Word::empty())])),
        });
        // The first patch exceeds the word budget. The second fails after preparing the map update.
        for invalid_entry in [
            (
                StorageSlotName::mock(2),
                StorageSlotPatch::Value(StorageValuePatch::Create { value: Word::empty() }),
            ),
            (
                array_name,
                StorageSlotPatch::Array(StorageArrayPatch::Update {
                    entries: StorageArrayPatchEntries::new(StorageArrayLength::try_from(254)?, [])?,
                }),
            ),
        ] {
            let patch = AccountStoragePatch::from_entries([
                (map_name.clone(), map_update.clone()),
                invalid_entry,
            ])?;
            let mut storage = initial.clone();
            assert!(storage.apply_patch(&patch).is_err());
            assert_eq!(storage, initial);
        }
        Ok(())
    }
}
