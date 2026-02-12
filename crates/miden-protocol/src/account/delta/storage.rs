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
use crate::account::{StorageMap, StorageSlotContent, StorageSlotName, StorageSlotType};
use crate::{EMPTY_WORD, Felt, LexicographicWord, ZERO};

// ACCOUNT STORAGE DELTA
// ================================================================================================

/// The [`AccountStorageDelta`] stores the differences between two states of account storage.
///
/// The delta consists of a map from [`StorageSlotName`] to [`StorageSlotDelta`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStorageDelta {
    /// The updates to the slots of the account.
    deltas: BTreeMap<StorageSlotName, StorageSlotDelta>,
}

impl AccountStorageDelta {
    /// Creates a new, empty storage delta.
    pub fn new() -> Self {
        Self { deltas: BTreeMap::new() }
    }

    /// Creates a new storage delta from the provided slot deltas.
    pub fn from_raw(deltas: BTreeMap<StorageSlotName, StorageSlotDelta>) -> Self {
        Self { deltas }
    }

    /// Returns the delta for the provided slot name, or `None` if no delta exists.
    pub fn get(&self, slot_name: &StorageSlotName) -> Option<&StorageSlotDelta> {
        self.deltas.get(slot_name)
    }

    /// Returns an iterator over the slot deltas.
    pub(crate) fn slots(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageSlotDelta)> {
        self.deltas.iter()
    }

    /// Returns an iterator over the updated values in this storage delta.
    pub fn values(&self) -> impl Iterator<Item = (&StorageSlotName, &Word)> {
        self.deltas.iter().filter_map(|(slot_name, slot_delta)| match slot_delta {
            StorageSlotDelta::Value(word) => Some((slot_name, word)),
            StorageSlotDelta::Map(_) => None,
        })
    }

    /// Returns an iterator over the updated maps in this storage delta.
    pub fn maps(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageMapDelta)> {
        self.deltas.iter().filter_map(|(slot_name, slot_delta)| match slot_delta {
            StorageSlotDelta::Value(_) => None,
            StorageSlotDelta::Map(map_delta) => Some((slot_name, map_delta)),
        })
    }

    /// Returns true if storage delta contains no updates.
    pub fn is_empty(&self) -> bool {
        self.deltas.is_empty()
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
        if !self.deltas.get(&slot_name).map(StorageSlotDelta::is_value).unwrap_or(true) {
            return Err(AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name));
        }

        self.deltas.insert(slot_name, StorageSlotDelta::Value(new_slot_value));

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
        key: Word,
        new_value: Word,
    ) -> Result<(), AccountDeltaError> {
        match self
            .deltas
            .entry(slot_name.clone())
            .or_insert(StorageSlotDelta::Map(StorageMapDelta::default()))
        {
            StorageSlotDelta::Value(_) => {
                return Err(AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name));
            },
            StorageSlotDelta::Map(storage_map_delta) => {
                storage_map_delta.insert(key, new_value);
            },
        };

        Ok(())
    }

    /// Inserts an empty storage map delta for the provided slot name.
    ///
    /// This is useful for full state deltas to represent an empty map in the delta.
    ///
    /// This overwrites the existing slot delta, if any.
    pub fn insert_empty_map_delta(&mut self, slot_name: StorageSlotName) {
        self.deltas.insert(slot_name, StorageSlotDelta::with_empty_map());
    }

    /// Merges another delta into this one, overwriting any existing values.
    pub fn merge(&mut self, other: Self) -> Result<(), AccountDeltaError> {
        for (slot_name, slot_delta) in other.deltas {
            match self.deltas.entry(slot_name.clone()) {
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(slot_delta);
                },
                Entry::Occupied(mut occupied_entry) => {
                    occupied_entry.get_mut().merge(slot_delta).ok_or_else(|| {
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

    /// Appends the storage slots delta to the given `elements` from which the delta commitment will
    /// be computed.
    pub(super) fn append_delta_elements(&self, elements: &mut Vec<Felt>) {
        const DOMAIN_VALUE: Felt = Felt::new(2);
        const DOMAIN_MAP: Felt = Felt::new(3);

        for (slot_name, slot_delta) in self.deltas.iter() {
            let slot_id = slot_name.id();

            match slot_delta {
                StorageSlotDelta::Value(new_value) => {
                    elements.extend_from_slice(&[
                        DOMAIN_VALUE,
                        ZERO,
                        slot_id.suffix(),
                        slot_id.prefix(),
                    ]);
                    elements.extend_from_slice(new_value.as_elements());
                },
                StorageSlotDelta::Map(map_delta) => {
                    for (key, value) in map_delta.entries() {
                        elements.extend_from_slice(key.inner().as_elements());
                        elements.extend_from_slice(value.as_elements());
                    }

                    let num_changed_entries = Felt::try_from(map_delta.num_entries()).expect(
                        "number of changed entries should not exceed max representable felt",
                    );

                    elements.extend_from_slice(&[
                        DOMAIN_MAP,
                        num_changed_entries,
                        slot_id.suffix(),
                        slot_id.prefix(),
                    ]);
                    elements.extend_from_slice(EMPTY_WORD.as_elements());
                },
            }
        }
    }

    /// Consumes self and returns the underlying map of the storage delta.
    pub fn into_map(self) -> BTreeMap<StorageSlotName, StorageSlotDelta> {
        self.deltas
    }
}

impl Default for AccountStorageDelta {
    fn default() -> Self {
        Self::new()
    }
}

impl Serializable for AccountStorageDelta {
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

        let mut storage_map_delta_size = 0;
        for (slot_name, storage_map_delta) in self.maps() {
            // The serialized size of each entry is the combination of slot (key) and the delta
            // (value).
            storage_map_delta_size += slot_name.get_size_hint() + storage_map_delta.get_size_hint();
        }

        // Length Prefixes
        u8_size * 3 +
        // Cleared Values
        self.cleared_values().fold(0, |acc, slot_name| acc + slot_name.get_size_hint()) +
        // Updated Values
        self.updated_values().fold(0, |acc, (slot_name, slot_value)| {
            acc + slot_name.get_size_hint() + slot_value.get_size_hint()
        }) +
        // Storage Map Delta
        storage_map_delta_size
    }
}

impl Deserializable for AccountStorageDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut deltas = BTreeMap::new();

        let num_cleared_values = source.read_u8()?;
        for _ in 0..num_cleared_values {
            let cleared_value: StorageSlotName = source.read()?;
            deltas.insert(cleared_value, StorageSlotDelta::with_empty_value());
        }

        let num_updated_values = source.read_u8()?;
        for _ in 0..num_updated_values {
            let (updated_slot, updated_value) = source.read()?;
            deltas.insert(updated_slot, StorageSlotDelta::Value(updated_value));
        }

        let num_maps = source.read_u8()? as usize;
        deltas.extend(
            source
                .read_many::<(StorageSlotName, StorageMapDelta)>(num_maps)?
                .into_iter()
                .map(|(slot_name, map_delta)| (slot_name, StorageSlotDelta::Map(map_delta))),
        );

        Ok(Self::from_raw(deltas))
    }
}

// STORAGE SLOT DELTA
// ================================================================================================

/// The delta of a single storage slot.
///
/// - [`StorageSlotDelta::Value`] contains the value to which a value slot is updated.
/// - [`StorageSlotDelta::Map`] contains the [`StorageMapDelta`] which contains the key-value pairs
///   that were updated in a map slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageSlotDelta {
    Value(Word),
    Map(StorageMapDelta),
}

impl StorageSlotDelta {
    // CONSTANTS
    // ----------------------------------------------------------------------------------------

    /// The type byte for value slot deltas.
    const VALUE: u8 = 0;

    /// The type byte for map slot deltas.
    const MAP: u8 = 1;

    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Returns a new [`StorageSlotDelta::Value`] with an empty value.
    pub fn with_empty_value() -> Self {
        Self::Value(Word::empty())
    }

    /// Returns a new [`StorageSlotDelta::Map`] with an empty map delta.
    pub fn with_empty_map() -> Self {
        Self::Map(StorageMapDelta::default())
    }

    // ACCESSORS
    // ----------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotType`] of this slot delta.
    pub fn slot_type(&self) -> StorageSlotType {
        match self {
            StorageSlotDelta::Value(_) => StorageSlotType::Value,
            StorageSlotDelta::Map(_) => StorageSlotType::Map,
        }
    }

    /// Returns `true` if the slot delta is of type [`StorageSlotDelta::Value`], `false` otherwise.
    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }

    /// Returns `true` if the slot delta is of type [`StorageSlotDelta::Map`], `false` otherwise.
    pub fn is_map(&self) -> bool {
        matches!(self, Self::Map(_))
    }

    // MUTATORS
    // ----------------------------------------------------------------------------------------

    /// Unwraps a value slot delta into a [`Word`].
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `self` is not of type [`StorageSlotDelta::Value`].
    pub fn unwrap_value(self) -> Word {
        match self {
            StorageSlotDelta::Value(value) => value,
            StorageSlotDelta::Map(_) => panic!("called unwrap_value on a map slot delta"),
        }
    }

    /// Unwraps a map slot delta into a [`StorageMapDelta`].
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `self` is not of type [`StorageSlotDelta::Map`].
    pub fn unwrap_map(self) -> StorageMapDelta {
        match self {
            StorageSlotDelta::Value(_) => panic!("called unwrap_map on a value slot delta"),
            StorageSlotDelta::Map(map_delta) => map_delta,
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
            (StorageSlotDelta::Value(current_value), StorageSlotDelta::Value(new_value)) => {
                *current_value = new_value;
            },
            (StorageSlotDelta::Map(current_map_delta), StorageSlotDelta::Map(new_map_delta)) => {
                current_map_delta.merge(new_map_delta);
            },
            (..) => {
                return None;
            },
        }

        Some(())
    }
}

impl From<StorageSlotContent> for StorageSlotDelta {
    fn from(content: StorageSlotContent) -> Self {
        match content {
            StorageSlotContent::Value(word) => StorageSlotDelta::Value(word),
            StorageSlotContent::Map(storage_map) => {
                StorageSlotDelta::Map(StorageMapDelta::from(storage_map))
            },
        }
    }
}

impl Serializable for StorageSlotDelta {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            StorageSlotDelta::Value(value) => {
                target.write_u8(Self::VALUE);
                target.write(value);
            },
            StorageSlotDelta::Map(storage_map_delta) => {
                target.write_u8(Self::MAP);
                target.write(storage_map_delta);
            },
        }
    }
}

impl Deserializable for StorageSlotDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::VALUE => {
                let value = source.read()?;
                Ok(Self::Value(value))
            },
            Self::MAP => {
                let map_delta = source.read()?;
                Ok(Self::Map(map_delta))
            },
            other => Err(DeserializationError::InvalidValue(format!(
                "unknown storage slot delta variant {other}"
            ))),
        }
    }
}

// STORAGE MAP DELTA
// ================================================================================================

/// [StorageMapDelta] stores the differences between two states of account storage maps.
///
/// The differences are represented as leaf updates: a map of updated item key ([Word]) to
/// value ([Word]). For cleared items the value is [EMPTY_WORD].
///
/// The [`LexicographicWord`] wrapper is necessary to order the keys in the same way as the
/// in-kernel account delta which uses a link map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageMapDelta(BTreeMap<LexicographicWord, Word>);

impl StorageMapDelta {
    /// Creates a new storage map delta from the provided leaves.
    pub fn new(map: BTreeMap<LexicographicWord, Word>) -> Self {
        Self(map)
    }

    /// Returns the number of changed entries in this map delta.
    pub fn num_entries(&self) -> usize {
        self.0.len()
    }

    /// Returns a reference to the updated entries in this storage map delta.
    ///
    /// Note that the returned key is the raw map key.
    pub fn entries(&self) -> &BTreeMap<LexicographicWord, Word> {
        &self.0
    }

    /// Inserts an item into the storage map delta.
    pub fn insert(&mut self, raw_key: Word, value: Word) {
        self.0.insert(LexicographicWord::new(raw_key), value);
    }

    /// Returns true if storage map delta contains no updates.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Merge `other` into this delta, giving precedence to `other`.
    pub fn merge(&mut self, other: Self) {
        // Aggregate the changes into a map such that `other` overwrites self.
        self.0.extend(other.0);
    }

    /// Returns a mutable reference to the underlying map.
    pub fn as_map_mut(&mut self) -> &mut BTreeMap<LexicographicWord, Word> {
        &mut self.0
    }

    /// Returns an iterator of all the cleared keys in the storage map.
    fn cleared_keys(&self) -> impl Iterator<Item = &Word> + '_ {
        self.0.iter().filter(|&(_, value)| value.is_empty()).map(|(key, _)| key.inner())
    }

    /// Returns an iterator of all the updated entries in the storage map.
    fn updated_entries(&self) -> impl Iterator<Item = (&Word, &Word)> + '_ {
        self.0.iter().filter_map(|(key, value)| {
            if !value.is_empty() {
                Some((key.inner(), value))
            } else {
                None
            }
        })
    }
}

#[cfg(any(feature = "testing", test))]
impl StorageMapDelta {
    /// Creates a new [StorageMapDelta] from the provided iterators.
    pub fn from_iters(
        cleared_leaves: impl IntoIterator<Item = Word>,
        updated_leaves: impl IntoIterator<Item = (Word, Word)>,
    ) -> Self {
        Self(BTreeMap::from_iter(
            cleared_leaves
                .into_iter()
                .map(|key| (LexicographicWord::new(key), EMPTY_WORD))
                .chain(
                    updated_leaves
                        .into_iter()
                        .map(|(key, value)| (LexicographicWord::new(key), value)),
                ),
        ))
    }

    /// Consumes self and returns the underlying map.
    pub fn into_map(self) -> BTreeMap<LexicographicWord, Word> {
        self.0
    }
}

/// Converts a [StorageMap] into a [StorageMapDelta] for initial delta construction.
impl From<StorageMap> for StorageMapDelta {
    fn from(map: StorageMap) -> Self {
        StorageMapDelta::new(
            map.into_entries()
                .into_iter()
                .map(|(key, value)| (LexicographicWord::new(key), value))
                .collect(),
        )
    }
}

impl Serializable for StorageMapDelta {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let cleared: Vec<&Word> = self.cleared_keys().collect();
        let updated: Vec<(&Word, &Word)> = self.updated_entries().collect();

        target.write_usize(cleared.len());
        target.write_many(cleared.iter());

        target.write_usize(updated.len());
        target.write_many(updated.iter());
    }

    fn get_size_hint(&self) -> usize {
        let word_size = EMPTY_WORD.get_size_hint();

        let cleared_keys_count = self.cleared_keys().count();
        let updated_entries_count = self.updated_entries().count();

        // Cleared Keys
        cleared_keys_count.get_size_hint() +
        cleared_keys_count * Word::SERIALIZED_SIZE +

        // Updated Entries
        updated_entries_count.get_size_hint() +
        updated_entries_count * (Word::SERIALIZED_SIZE + word_size)
    }
}

impl Deserializable for StorageMapDelta {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut map = BTreeMap::new();

        let cleared_count = source.read_usize()?;
        for _ in 0..cleared_count {
            let cleared_key = source.read()?;
            map.insert(LexicographicWord::new(cleared_key), EMPTY_WORD);
        }

        let updated_count = source.read_usize()?;
        for _ in 0..updated_count {
            let (updated_key, updated_value) = source.read()?;
            map.insert(LexicographicWord::new(updated_key), updated_value);
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

    use super::{AccountStorageDelta, Deserializable, Serializable};
    use crate::account::{StorageMapDelta, StorageSlotDelta, StorageSlotName};
    use crate::errors::AccountDeltaError;
    use crate::{ONE, Word};

    #[test]
    fn account_storage_delta_returns_err_on_slot_type_mismatch() {
        let value_slot_name = StorageSlotName::mock(1);
        let map_slot_name = StorageSlotName::mock(2);

        let mut delta = AccountStorageDelta::from_iters(
            [value_slot_name.clone()],
            [],
            [(map_slot_name.clone(), StorageMapDelta::default())],
        );

        let err = delta
            .set_map_item(value_slot_name.clone(), Word::empty(), Word::empty())
            .unwrap_err();
        assert_matches!(err, AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name) => {
            assert_eq!(value_slot_name, slot_name)
        });

        let err = delta.set_item(map_slot_name.clone(), Word::empty()).unwrap_err();
        assert_matches!(err, AccountDeltaError::StorageSlotUsedAsDifferentTypes(slot_name) => {
            assert_eq!(map_slot_name, slot_name)
        });
    }

    #[test]
    fn test_is_empty() {
        let storage_delta = AccountStorageDelta::new();
        assert!(storage_delta.is_empty());

        let storage_delta = AccountStorageDelta::from_iters([StorageSlotName::mock(1)], [], []);
        assert!(!storage_delta.is_empty());

        let storage_delta = AccountStorageDelta::from_iters(
            [],
            [(StorageSlotName::mock(2), Word::from([ONE, ONE, ONE, ONE]))],
            [],
        );
        assert!(!storage_delta.is_empty());

        let storage_delta = AccountStorageDelta::from_iters(
            [],
            [],
            [(StorageSlotName::mock(3), StorageMapDelta::default())],
        );
        assert!(!storage_delta.is_empty());
    }

    #[test]
    fn test_serde_account_storage_delta() {
        let storage_delta = AccountStorageDelta::new();
        let serialized = storage_delta.to_bytes();
        let deserialized = AccountStorageDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_delta);

        let storage_delta = AccountStorageDelta::from_iters([StorageSlotName::mock(1)], [], []);
        let serialized = storage_delta.to_bytes();
        let deserialized = AccountStorageDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_delta);

        let storage_delta = AccountStorageDelta::from_iters(
            [],
            [(StorageSlotName::mock(2), Word::from([ONE, ONE, ONE, ONE]))],
            [],
        );
        let serialized = storage_delta.to_bytes();
        let deserialized = AccountStorageDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_delta);

        let storage_delta = AccountStorageDelta::from_iters(
            [],
            [],
            [(StorageSlotName::mock(3), StorageMapDelta::default())],
        );
        let serialized = storage_delta.to_bytes();
        let deserialized = AccountStorageDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_delta);
    }

    #[test]
    fn test_serde_storage_map_delta() {
        let storage_map_delta = StorageMapDelta::default();
        let serialized = storage_map_delta.to_bytes();
        let deserialized = StorageMapDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_map_delta);

        let storage_map_delta = StorageMapDelta::from_iters([Word::from([ONE, ONE, ONE, ONE])], []);
        let serialized = storage_map_delta.to_bytes();
        let deserialized = StorageMapDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_map_delta);

        let storage_map_delta =
            StorageMapDelta::from_iters([], [(Word::empty(), Word::from([ONE, ONE, ONE, ONE]))]);
        let serialized = storage_map_delta.to_bytes();
        let deserialized = StorageMapDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage_map_delta);
    }

    #[test]
    fn test_serde_storage_slot_value_delta() {
        let slot_delta = StorageSlotDelta::with_empty_value();
        let serialized = slot_delta.to_bytes();
        let deserialized = StorageSlotDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_delta);

        let slot_delta = StorageSlotDelta::Value(Word::from([1, 2, 3, 4u32]));
        let serialized = slot_delta.to_bytes();
        let deserialized = StorageSlotDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_delta);
    }

    #[test]
    fn test_serde_storage_slot_map_delta() {
        let slot_delta = StorageSlotDelta::with_empty_map();
        let serialized = slot_delta.to_bytes();
        let deserialized = StorageSlotDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_delta);

        let map_delta = StorageMapDelta::from_iters(
            [Word::from([1, 2, 3, 4u32])],
            [(Word::from([5, 6, 7, 8u32]), Word::from([3, 4, 5, 6u32]))],
        );
        let slot_delta = StorageSlotDelta::Map(map_delta);
        let serialized = slot_delta.to_bytes();
        let deserialized = StorageSlotDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, slot_delta);
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
        /// Creates a delta containing the item as an update if Some, else with the item cleared.
        fn create_delta(item: Option<u32>) -> AccountStorageDelta {
            let slot_name = StorageSlotName::mock(123);
            let item = item.map(|x| (slot_name.clone(), Word::from([x, 0, 0, 0])));

            AccountStorageDelta::new()
                .add_cleared_items(item.is_none().then_some(slot_name.clone()))
                .add_updated_values(item)
        }

        let mut delta_x = create_delta(x);
        let delta_y = create_delta(y);
        let expected = create_delta(expected);

        delta_x.merge(delta_y).context("failed to merge deltas")?;

        assert_eq!(delta_x, expected);

        Ok(())
    }

    #[rstest::rstest]
    #[case::some_some(Some(1), Some(2), Some(2))]
    #[case::none_some(None, Some(2), Some(2))]
    #[case::some_none(Some(1), None, None)]
    #[test]
    fn merge_maps(#[case] x: Option<u32>, #[case] y: Option<u32>, #[case] expected: Option<u32>) {
        fn create_delta(value: Option<u32>) -> StorageMapDelta {
            let key = Word::from([10u32, 0, 0, 0]);
            match value {
                Some(value) => {
                    StorageMapDelta::from_iters([], [(key, Word::from([value, 0, 0, 0]))])
                },
                None => StorageMapDelta::from_iters([key], []),
            }
        }

        let mut delta_x = create_delta(x);
        let delta_y = create_delta(y);
        let expected = create_delta(expected);

        delta_x.merge(delta_y);

        assert_eq!(delta_x, expected);
    }
}
