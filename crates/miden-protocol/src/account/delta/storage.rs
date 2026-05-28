use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec::Vec;

use super::{
    AccountDeltaError,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
    Word,
};
use crate::account::{
    StorageMap,
    StorageMapKey,
    StorageSlotContent,
    StorageSlotName,
    StorageSlotType,
};
use crate::{EMPTY_WORD, Felt, ZERO};

// ACCOUNT STORAGE PATCH
// ================================================================================================

/// The [`AccountStoragePatch`] stores the differences between two states of account storage.
///
/// The patch consists of a map from [`StorageSlotName`] to [`StorageSlotPatch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStoragePatch {
    /// The updates to the slots of the account.
    patches: BTreeMap<StorageSlotName, StorageSlotPatch>,
}

impl AccountStoragePatch {
    /// Creates a new, empty storage patch.
    pub fn new() -> Self {
        Self { patches: BTreeMap::new() }
    }

    /// Creates a new storage patch from the provided slot patches.
    pub fn from_raw(patches: BTreeMap<StorageSlotName, StorageSlotPatch>) -> Self {
        Self { patches }
    }

    /// Returns the patch for the provided slot name, or `None` if no patch exists.
    pub fn get(&self, slot_name: &StorageSlotName) -> Option<&StorageSlotPatch> {
        self.patches.get(slot_name)
    }

    /// Returns an iterator over the slot patches.
    pub(crate) fn slots(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageSlotPatch)> {
        self.patches.iter()
    }

    /// Returns an iterator over the updated values in this storage patch.
    pub fn values(&self) -> impl Iterator<Item = (&StorageSlotName, &Word)> {
        self.patches.iter().filter_map(|(slot_name, slot_patch)| match slot_patch {
            StorageSlotPatch::Value(word) => Some((slot_name, word)),
            StorageSlotPatch::Map(_) => None,
        })
    }

    /// Returns an iterator over the updated maps in this storage patch.
    pub fn maps(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageMapPatch)> {
        self.patches.iter().filter_map(|(slot_name, slot_patch)| match slot_patch {
            StorageSlotPatch::Value(_) => None,
            StorageSlotPatch::Map(map_patch) => Some((slot_name, map_patch)),
        })
    }

    /// Returns true if storage patch contains no updates.
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Tracks a slot change.
    ///
    /// This does not (and cannot) validate that the slot name _exists_ or that it points to a
    /// _value_ slot in the corresponding account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the slot name points to an existing slot that is not of type value.
    pub fn set_item(
        &mut self,
        slot_name: StorageSlotName,
        new_slot_value: Word,
    ) -> Result<(), AccountDeltaError> {
        if !self.patches.get(&slot_name).map(StorageSlotPatch::is_value).unwrap_or(true) {
            return Err(AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name));
        }

        self.patches.insert(slot_name, StorageSlotPatch::Value(new_slot_value));

        Ok(())
    }

    /// Tracks a map item change.
    ///
    /// This does not (and cannot) validate that the slot name _exists_ or that it points to a
    /// _map_ slot in the corresponding account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the slot name points to an existing slot that is not of type map.
    pub fn set_map_item(
        &mut self,
        slot_name: StorageSlotName,
        key: StorageMapKey,
        new_value: Word,
    ) -> Result<(), AccountDeltaError> {
        match self
            .patches
            .entry(slot_name.clone())
            .or_insert(StorageSlotPatch::Map(StorageMapPatch::default()))
        {
            StorageSlotPatch::Value(_) => {
                return Err(AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name));
            },
            StorageSlotPatch::Map(storage_map_patch) => {
                storage_map_patch.insert(key, new_value);
            },
        };

        Ok(())
    }

    /// Inserts an empty storage map patch for the provided slot name.
    ///
    /// This is useful for full state patches to represent an empty map in the patch.
    ///
    /// This overwrites the existing slot patch, if any.
    pub fn insert_empty_map_patch(&mut self, slot_name: StorageSlotName) {
        self.patches.insert(slot_name, StorageSlotPatch::with_empty_map());
    }

    /// Merges another patch into this one, overwriting any existing values.
    pub fn merge(&mut self, other: Self) -> Result<(), AccountDeltaError> {
        for (slot_name, slot_patch) in other.patches {
            match self.patches.entry(slot_name.clone()) {
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(slot_patch);
                },
                Entry::Occupied(mut occupied_entry) => {
                    occupied_entry.get_mut().merge(slot_patch).ok_or_else(|| {
                        AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name)
                    })?;
                },
            }
        }

        Ok(())
    }

    /// Returns an iterator of all the cleared storage slots.
    fn cleared_values(&self) -> impl Iterator<Item = &StorageSlotName> {
        self.values().filter_map(
            |(slot_name, slot_value)| {
                if slot_value.is_empty() { Some(slot_name) } else { None }
            },
        )
    }

    /// Returns an iterator of all the updated storage slots.
    fn updated_values(&self) -> impl Iterator<Item = (&StorageSlotName, &Word)> {
        self.values().filter_map(|(slot_name, slot_value)| {
            if !slot_value.is_empty() {
                Some((slot_name, slot_value))
            } else {
                None
            }
        })
    }

    /// Appends the storage slots patch to the given `elements` from which the delta commitment will
    /// be computed.
    pub(super) fn append_delta_elements(&self, elements: &mut Vec<Felt>) {
        let domain_value = Felt::from_u8(2);
        let domain_map = Felt::from_u8(3);

        for (slot_name, slot_patch) in self.patches.iter() {
            let slot_id = slot_name.id();

            match slot_patch {
                StorageSlotPatch::Value(new_value) => {
                    elements.extend_from_slice(&[
                        domain_value,
                        ZERO,
                        slot_id.suffix(),
                        slot_id.prefix(),
                    ]);
                    elements.extend_from_slice(new_value.as_elements());
                },
                StorageSlotPatch::Map(map_patch) => {
                    for (key, value) in map_patch.entries() {
                        elements.extend_from_slice(key.as_elements());
                        elements.extend_from_slice(value.as_elements());
                    }

                    let num_changed_entries = Felt::try_from(map_patch.num_entries() as u64)
                        .expect(
                            "number of changed entries should not exceed max representable felt",
                        );

                    elements.extend_from_slice(&[
                        domain_map,
                        num_changed_entries,
                        slot_id.suffix(),
                        slot_id.prefix(),
                    ]);
                    elements.extend_from_slice(EMPTY_WORD.as_elements());
                },
            }
        }
    }

    /// Consumes self and returns the underlying map of the storage patch.
    pub fn into_map(self) -> BTreeMap<StorageSlotName, StorageSlotPatch> {
        self.patches
    }
}

impl Default for AccountStoragePatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Serializable for AccountStoragePatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let num_cleared_values = self.cleared_values().count();
        let num_cleared_values =
            u8::try_from(num_cleared_values).expect("number of slots should fit in u8");
        let cleared_values = self.cleared_values();

        let num_updated_values = self.updated_values().count();
        let num_updated_values =
            u8::try_from(num_updated_values).expect("number of slots should fit in u8");
        let updated_values = self.updated_values();

        let num_maps = self.maps().count();
        let num_maps = u8::try_from(num_maps).expect("number of slots should fit in u8");
        let maps = self.maps();

        target.write_u8(num_cleared_values);
        target.write_many(cleared_values);

        target.write_u8(num_updated_values);
        target.write_many(updated_values);

        target.write_u8(num_maps);
        target.write_many(maps);
    }

    fn get_size_hint(&self) -> usize {
        let u8_size = 0u8.get_size_hint();

        let mut storage_map_patch_size = 0;
        for (slot_name, storage_map_patch) in self.maps() {
            // The serialized size of each entry is the combination of slot (key) and the patch
            // (value).
            storage_map_patch_size += slot_name.get_size_hint() + storage_map_patch.get_size_hint();
        }

        // Length Prefixes
        u8_size * 3 +
        // Cleared Values
        self.cleared_values().fold(0, |acc, slot_name| acc + slot_name.get_size_hint()) +
        // Updated Values
        self.updated_values().fold(0, |acc, (slot_name, slot_value)| {
            acc + slot_name.get_size_hint() + slot_value.get_size_hint()
        }) +
        // Storage Map Patch
        storage_map_patch_size
    }
}

impl Deserializable for AccountStoragePatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut patches = BTreeMap::new();

        let num_cleared_values = source.read_u8()?;
        for _ in 0..num_cleared_values {
            let cleared_value: StorageSlotName = source.read()?;
            patches.insert(cleared_value, StorageSlotPatch::with_empty_value());
        }

        let num_updated_values = source.read_u8()?;
        for _ in 0..num_updated_values {
            let (updated_slot, updated_value) = source.read()?;
            patches.insert(updated_slot, StorageSlotPatch::Value(updated_value));
        }

        let num_maps = source.read_u8()? as usize;
        for read_result in source.read_many_iter::<(StorageSlotName, StorageMapPatch)>(num_maps)? {
            let (slot_name, map_patch) = read_result?;
            patches.insert(slot_name, StorageSlotPatch::Map(map_patch));
        }

        Ok(Self::from_raw(patches))
    }
}

// STORAGE SLOT PATCH
// ================================================================================================

/// The patch of a single storage slot.
///
/// - [`StorageSlotPatch::Value`] contains the value to which a value slot is updated.
/// - [`StorageSlotPatch::Map`] contains the [`StorageMapPatch`] which contains the key-value pairs
///   that were updated in a map slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageSlotPatch {
    Value(Word),
    Map(StorageMapPatch),
}

impl StorageSlotPatch {
    // CONSTANTS
    // ----------------------------------------------------------------------------------------

    /// The type byte for value slot patches.
    const VALUE: u8 = 0;

    /// The type byte for map slot patches.
    const MAP: u8 = 1;

    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Returns a new [`StorageSlotPatch::Value`] with an empty value.
    pub fn with_empty_value() -> Self {
        Self::Value(Word::empty())
    }

    /// Returns a new [`StorageSlotPatch::Map`] with an empty map patch.
    pub fn with_empty_map() -> Self {
        Self::Map(StorageMapPatch::default())
    }

    // ACCESSORS
    // ----------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotType`] of this slot patch.
    pub fn slot_type(&self) -> StorageSlotType {
        match self {
            StorageSlotPatch::Value(_) => StorageSlotType::Value,
            StorageSlotPatch::Map(_) => StorageSlotType::Map,
        }
    }

    /// Returns `true` if the slot patch is of type [`StorageSlotPatch::Value`], `false` otherwise.
    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }

    /// Returns `true` if the slot patch is of type [`StorageSlotPatch::Map`], `false` otherwise.
    pub fn is_map(&self) -> bool {
        matches!(self, Self::Map(_))
    }

    // MUTATORS
    // ----------------------------------------------------------------------------------------

    /// Unwraps a value slot patch into a [`Word`].
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `self` is not of type [`StorageSlotPatch::Value`].
    pub fn unwrap_value(self) -> Word {
        match self {
            StorageSlotPatch::Value(value) => value,
            StorageSlotPatch::Map(_) => panic!("called unwrap_value on a map slot patch"),
        }
    }

    /// Unwraps a map slot patch into a [`StorageMapPatch`].
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `self` is not of type [`StorageSlotPatch::Map`].
    pub fn unwrap_map(self) -> StorageMapPatch {
        match self {
            StorageSlotPatch::Value(_) => panic!("called unwrap_map on a value slot patch"),
            StorageSlotPatch::Map(map_patch) => map_patch,
        }
    }

    /// Merges `other` into `self`.
    ///
    /// # Errors
    ///
    /// Returns `None` if:
    /// - merging failed due to a slot type mismatch.
    #[must_use]
    fn merge(&mut self, other: Self) -> Option<()> {
        match (self, other) {
            (StorageSlotPatch::Value(current_value), StorageSlotPatch::Value(new_value)) => {
                *current_value = new_value;
            },
            (StorageSlotPatch::Map(current_map_patch), StorageSlotPatch::Map(new_map_patch)) => {
                current_map_patch.merge(new_map_patch);
            },
            (..) => {
                return None;
            },
        }

        Some(())
    }
}

impl From<StorageSlotContent> for StorageSlotPatch {
    fn from(content: StorageSlotContent) -> Self {
        match content {
            StorageSlotContent::Value(word) => StorageSlotPatch::Value(word),
            StorageSlotContent::Map(storage_map) => {
                StorageSlotPatch::Map(StorageMapPatch::from(storage_map))
            },
        }
    }
}

impl Serializable for StorageSlotPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            StorageSlotPatch::Value(value) => {
                target.write_u8(Self::VALUE);
                target.write(value);
            },
            StorageSlotPatch::Map(storage_map_patch) => {
                target.write_u8(Self::MAP);
                target.write(storage_map_patch);
            },
        }
    }
}

impl Deserializable for StorageSlotPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::VALUE => {
                let value = source.read()?;
                Ok(Self::Value(value))
            },
            Self::MAP => {
                let map_patch = source.read()?;
                Ok(Self::Map(map_patch))
            },
            other => Err(DeserializationError::InvalidValue(format!(
                "unknown storage slot patch variant {other}"
            ))),
        }
    }
}

// STORAGE MAP PATCH
// ================================================================================================

/// [StorageMapPatch] stores the differences between two states of account storage maps.
///
/// The differences are represented as leaf updates: a map of updated item key ([Word]) to
/// value ([Word]). For cleared items the value is [EMPTY_WORD].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageMapPatch(BTreeMap<StorageMapKey, Word>);

impl StorageMapPatch {
    /// Creates a new storage map patch from the provided leaves.
    pub fn new(map: BTreeMap<StorageMapKey, Word>) -> Self {
        Self(map)
    }

    /// Returns the number of changed entries in this map patch.
    pub fn num_entries(&self) -> usize {
        self.0.len()
    }

    /// Returns a reference to the updated entries in this storage map patch.
    ///
    /// Note that the returned key is the [`StorageMapKey`].
    pub fn entries(&self) -> &BTreeMap<StorageMapKey, Word> {
        &self.0
    }

    /// Inserts an item into the storage map patch.
    pub fn insert(&mut self, key: StorageMapKey, value: Word) {
        self.0.insert(key, value);
    }

    /// Returns true if storage map patch contains no updates.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Merge `other` into this patch, giving precedence to `other`.
    pub fn merge(&mut self, other: Self) {
        // Aggregate the changes into a map such that `other` overwrites self.
        self.0.extend(other.0);
    }

    /// Returns a mutable reference to the underlying map.
    pub fn as_map_mut(&mut self) -> &mut BTreeMap<StorageMapKey, Word> {
        &mut self.0
    }

    /// Returns an iterator of all the cleared keys in the storage map.
    fn cleared_keys(&self) -> impl Iterator<Item = &StorageMapKey> + '_ {
        self.0.iter().filter(|&(_, value)| value.is_empty()).map(|(key, _)| key)
    }

    /// Returns an iterator of all the updated entries in the storage map.
    fn updated_entries(&self) -> impl Iterator<Item = (&StorageMapKey, &Word)> + '_ {
        self.0.iter().filter_map(
            |(key, value)| {
                if !value.is_empty() { Some((key, value)) } else { None }
            },
        )
    }
}

#[cfg(any(feature = "testing", test))]
impl StorageMapPatch {
    /// Creates a new [StorageMapPatch] from the provided iterators.
    pub fn from_iters(
        cleared_leaves: impl IntoIterator<Item = StorageMapKey>,
        updated_leaves: impl IntoIterator<Item = (StorageMapKey, Word)>,
    ) -> Self {
        Self(BTreeMap::from_iter(
            cleared_leaves.into_iter().map(|key| (key, EMPTY_WORD)).chain(updated_leaves),
        ))
    }

    /// Consumes self and returns the underlying map.
    pub fn into_map(self) -> BTreeMap<StorageMapKey, Word> {
        self.0
    }
}

/// Converts a [StorageMap] into a [StorageMapPatch] for initial patch construction.
impl From<StorageMap> for StorageMapPatch {
    fn from(map: StorageMap) -> Self {
        StorageMapPatch::new(map.into_entries().into_iter().collect())
    }
}

impl Serializable for StorageMapPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let cleared: Vec<&StorageMapKey> = self.cleared_keys().collect();
        let updated: Vec<(&StorageMapKey, &Word)> = self.updated_entries().collect();

        target.write_usize(cleared.len());
        target.write_many(cleared.iter());

        target.write_usize(updated.len());
        target.write_many(updated.iter());
    }

    fn get_size_hint(&self) -> usize {
        let cleared_keys_count = self.cleared_keys().count();
        let updated_entries_count = self.updated_entries().count();

        // Cleared Keys
        cleared_keys_count.get_size_hint() +
        cleared_keys_count * StorageMapKey::SERIALIZED_SIZE +

        // Updated Entries
        updated_entries_count.get_size_hint() +
        updated_entries_count * (StorageMapKey::SERIALIZED_SIZE + Word::SERIALIZED_SIZE)
    }
}

impl Deserializable for StorageMapPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut map = BTreeMap::new();

        let cleared_count = source.read_usize()?;
        for _ in 0..cleared_count {
            let cleared_key = source.read()?;
            map.insert(cleared_key, EMPTY_WORD);
        }

        let updated_count = source.read_usize()?;
        for _ in 0..updated_count {
            let (updated_key, updated_value) = source.read()?;
            map.insert(updated_key, updated_value);
        }

        Ok(Self::new(map))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use assert_matches::assert_matches;

    use super::{AccountStoragePatch, Deserializable, Serializable};
    use crate::account::{StorageMapKey, StorageMapPatch, StorageSlotName, StorageSlotPatch};
    use crate::errors::AccountDeltaError;
    use crate::{ONE, Word};

    #[test]
    fn account_storage_patch_returns_err_on_slot_type_mismatch() {
        let value_slot_name = StorageSlotName::mock(1);
        let map_slot_name = StorageSlotName::mock(2);

        let mut patch = AccountStoragePatch::from_iters(
            [value_slot_name.clone()],
            [],
            [(map_slot_name.clone(), StorageMapPatch::default())],
        );

        let err = patch
            .set_map_item(value_slot_name.clone(), StorageMapKey::empty(), Word::empty())
            .unwrap_err();
        assert_matches!(err, AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name) => {
            assert_eq!(value_slot_name, slot_name)
        });

        let err = patch.set_item(map_slot_name.clone(), Word::empty()).unwrap_err();
        assert_matches!(err, AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name) => {
            assert_eq!(map_slot_name, slot_name)
        });
    }

    #[test]
    fn test_is_empty() {
        let storage_patch = AccountStoragePatch::new();
        assert!(storage_patch.is_empty());

        let storage_patch = AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []);
        assert!(!storage_patch.is_empty());

        let storage_patch = AccountStoragePatch::from_iters(
            [],
            [(StorageSlotName::mock(2), Word::from([ONE, ONE, ONE, ONE]))],
            [],
        );
        assert!(!storage_patch.is_empty());

        let storage_patch = AccountStoragePatch::from_iters(
            [],
            [],
            [(StorageSlotName::mock(3), StorageMapPatch::default())],
        );
        assert!(!storage_patch.is_empty());
    }

    #[test]
    fn test_serde_account_storage_patch() {
        let storage_patch = AccountStoragePatch::new();
        let serialized = storage_patch.to_bytes();
        let deserialized = AccountStoragePatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_patch);
        assert_eq!(storage_patch.get_size_hint(), serialized.len());

        let storage_patch = AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []);
        let serialized = storage_patch.to_bytes();
        let deserialized = AccountStoragePatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_patch);
        assert_eq!(storage_patch.get_size_hint(), serialized.len());

        let storage_patch = AccountStoragePatch::from_iters(
            [],
            [(StorageSlotName::mock(2), Word::from([ONE, ONE, ONE, ONE]))],
            [],
        );
        let serialized = storage_patch.to_bytes();
        let deserialized = AccountStoragePatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_patch);
        assert_eq!(storage_patch.get_size_hint(), serialized.len());

        let storage_patch = AccountStoragePatch::from_iters(
            [],
            [],
            [(StorageSlotName::mock(3), StorageMapPatch::default())],
        );
        let serialized = storage_patch.to_bytes();
        let deserialized = AccountStoragePatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_patch);
        assert_eq!(storage_patch.get_size_hint(), serialized.len());
    }

    #[test]
    fn test_serde_storage_map_patch() {
        let storage_map_patch = StorageMapPatch::default();
        let serialized = storage_map_patch.to_bytes();
        let deserialized = StorageMapPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_map_patch);

        let storage_map_patch =
            StorageMapPatch::from_iters([StorageMapKey::from_array([1, 1, 1, 1])], []);
        let serialized = storage_map_patch.to_bytes();
        let deserialized = StorageMapPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_map_patch);

        let storage_map_patch = StorageMapPatch::from_iters(
            [],
            [(StorageMapKey::empty(), Word::from([ONE, ONE, ONE, ONE]))],
        );
        let serialized = storage_map_patch.to_bytes();
        let deserialized = StorageMapPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_map_patch);
    }

    #[test]
    fn test_serde_storage_slot_value_patch() {
        let slot_patch = StorageSlotPatch::with_empty_value();
        let serialized = slot_patch.to_bytes();
        let deserialized = StorageSlotPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_patch);

        let slot_patch = StorageSlotPatch::Value(Word::from([1, 2, 3, 4u32]));
        let serialized = slot_patch.to_bytes();
        let deserialized = StorageSlotPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_patch);
    }

    #[test]
    fn test_serde_storage_slot_map_patch() {
        let slot_patch = StorageSlotPatch::with_empty_map();
        let serialized = slot_patch.to_bytes();
        let deserialized = StorageSlotPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_patch);

        let map_patch = StorageMapPatch::from_iters(
            [StorageMapKey::from_array([1, 2, 3, 4])],
            [(StorageMapKey::from_array([5, 6, 7, 8]), Word::from([3, 4, 5, 6u32]))],
        );
        let slot_patch = StorageSlotPatch::Map(map_patch);
        let serialized = slot_patch.to_bytes();
        let deserialized = StorageSlotPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_patch);
    }

    #[rstest::rstest]
    #[case::some_some(Some(1), Some(2), Some(2))]
    #[case::none_some(None, Some(2), Some(2))]
    #[case::some_none(Some(1), None, None)]
    #[test]
    fn merge_items(
        #[case] x: Option<u32>,
        #[case] y: Option<u32>,
        #[case] expected: Option<u32>,
    ) -> anyhow::Result<()> {
        /// Creates a patch containing the item as an update if Some, else with the item cleared.
        fn create_patch(item: Option<u32>) -> AccountStoragePatch {
            let slot_name = StorageSlotName::mock(123);
            let item = item.map(|x| (slot_name.clone(), Word::from([x, 0, 0, 0])));

            AccountStoragePatch::new()
                .add_cleared_items(item.is_none().then_some(slot_name.clone()))
                .add_updated_values(item)
        }

        let mut patch_x = create_patch(x);
        let patch_y = create_patch(y);
        let expected = create_patch(expected);

        patch_x.merge(patch_y).context("failed to merge patches")?;

        assert_eq!(patch_x, expected);

        Ok(())
    }

    #[rstest::rstest]
    #[case::some_some(Some(1), Some(2), Some(2))]
    #[case::none_some(None, Some(2), Some(2))]
    #[case::some_none(Some(1), None, None)]
    #[test]
    fn merge_maps(#[case] x: Option<u32>, #[case] y: Option<u32>, #[case] expected: Option<u32>) {
        fn create_patch(value: Option<u32>) -> StorageMapPatch {
            let key = StorageMapKey::from_array([10, 0, 0, 0]);
            match value {
                Some(value) => {
                    StorageMapPatch::from_iters([], [(key, Word::from([value, 0, 0, 0]))])
                },
                None => StorageMapPatch::from_iters([key], []),
            }
        }

        let mut patch_x = create_patch(x);
        let patch_y = create_patch(y);
        let expected = create_patch(expected);

        patch_x.merge(patch_y);

        assert_eq!(patch_x, expected);
    }
}
