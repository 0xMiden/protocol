use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::{
    StorageMap,
    StorageMapKey,
    StorageSlotContent,
    StorageSlotName,
    StorageSlotType,
};
use crate::errors::AccountPatchError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{EMPTY_WORD, Felt, Word, ZERO};

// ACCOUNT STORAGE PATCH
// ================================================================================================

/// The [`AccountStoragePatch`] stores the changes between two states of account storage.
///
/// The patch consists of a map from [`StorageSlotName`] to [`StorageSlotPatch`], where each slot
/// patch records whether the slot was created, updated, or removed (see [`StorageValuePatch`] and
/// [`StorageMapPatch`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStoragePatch {
    /// The patches to the slots of the account.
    patches: BTreeMap<StorageSlotName, StorageSlotPatch>,
}

impl AccountStoragePatch {
    /// Domain separator for value storage slots in delta and patch commitments.
    const DOMAIN_VALUE: Felt = Felt::new_unchecked(5);

    /// Domain separator for map storage slots in delta and patch commitments.
    const DOMAIN_MAP: Felt = Felt::new_unchecked(6);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new, empty storage patch.
    pub fn new() -> Self {
        Self { patches: BTreeMap::new() }
    }

    /// Creates a new storage patch from the provided map of slot patches.
    ///
    /// Because the input is already a map keyed by slot name, slot name uniqueness holds by
    /// construction. Use [`AccountStoragePatch::from_entries`] to build a patch from a sequence
    /// that may contain duplicates.
    pub fn from_raw(patches: BTreeMap<StorageSlotName, StorageSlotPatch>) -> Self {
        Self { patches }
    }

    /// Creates a new storage patch from the provided sequence of slot patches.
    ///
    /// # Errors
    ///
    /// Returns an error if the same [`StorageSlotName`] appears more than once.
    pub fn from_entries(
        entries: impl IntoIterator<Item = (StorageSlotName, StorageSlotPatch)>,
    ) -> Result<Self, AccountPatchError> {
        let mut patches = BTreeMap::new();
        for (slot_name, slot_patch) in entries {
            if patches.insert(slot_name.clone(), slot_patch).is_some() {
                return Err(AccountPatchError::DuplicateStorageSlotName(slot_name));
            }
        }

        Ok(Self::from_raw(patches))
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the patch for the provided slot name, or `None` if no patch exists.
    pub fn get(&self, slot_name: &StorageSlotName) -> Option<&StorageSlotPatch> {
        self.patches.get(slot_name)
    }

    /// Returns the number of slot patches.
    pub fn num_slots(&self) -> usize {
        self.patches.len()
    }

    /// Returns an iterator over the slot patches.
    pub(crate) fn slots(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageSlotPatch)> {
        self.patches.iter()
    }

    /// Returns an iterator over the value slot patches in this storage patch.
    pub fn values(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageValuePatch)> {
        self.patches.iter().filter_map(|(slot_name, slot_patch)| match slot_patch {
            StorageSlotPatch::Value(value_patch) => Some((slot_name, value_patch)),
            StorageSlotPatch::Map(_) => None,
        })
    }

    /// Returns an iterator over the map slot patches in this storage patch.
    pub fn maps(&self) -> impl Iterator<Item = (&StorageSlotName, &StorageMapPatch)> {
        self.patches.iter().filter_map(|(slot_name, slot_patch)| match slot_patch {
            StorageSlotPatch::Value(_) => None,
            StorageSlotPatch::Map(map_patch) => Some((slot_name, map_patch)),
        })
    }

    /// Returns true if storage patch contains no patches.
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Merges another patch into this one, with the entries of `other` taking precedence.
    pub fn merge(&mut self, other: Self) -> Result<(), AccountPatchError> {
        for (slot_name, slot_patch) in other.patches {
            match self.patches.get_mut(&slot_name) {
                None => {
                    self.patches.insert(slot_name, slot_patch);
                },
                Some(existing) => {
                    existing.merge(&slot_name, slot_patch)?;
                },
            }
        }

        Ok(())
    }

    /// Consumes self and returns the underlying map of the storage patch.
    pub fn into_map(self) -> BTreeMap<StorageSlotName, StorageSlotPatch> {
        self.patches
    }

    // COMMITMENT
    // --------------------------------------------------------------------------------------------

    /// Appends the storage slot patches to the given `elements` from which the delta or patch
    /// commitment is computed.
    ///
    /// TODO(storage_delta): Map [`StorageValuePatch::Create`] and [`StorageValuePatch::Update`]
    /// (and likewise for maps) to the current structure to match the transaction kernel's
    /// commitment. This will be refactored in a follow-up to include the delta ops in the
    /// commitment.
    pub(in crate::account) fn append_patch_elements(&self, elements: &mut Vec<Felt>) {
        for (slot_name, slot_patch) in self.patches.iter() {
            let slot_id = slot_name.id();

            match slot_patch {
                StorageSlotPatch::Value(value_patch) => {
                    elements.extend_from_slice(&[
                        Self::DOMAIN_VALUE,
                        ZERO,
                        slot_id.suffix(),
                        slot_id.prefix(),
                    ]);
                    elements.extend_from_slice(value_patch.committed_value().as_elements());
                },
                StorageSlotPatch::Map(map_patch) => {
                    let num_changed_entries = if let Some(map_entries) = map_patch.entries() {
                        for (key, value) in map_entries.as_map() {
                            elements.extend_from_slice(key.as_elements());
                            elements.extend_from_slice(value.as_elements());
                        }

                        map_entries.num_entries() as u64
                    } else {
                        // If the map slot was removed the number of removed entries is unknown and
                        // so we commit to 0 changed entries.
                        0
                    };
                    let num_changed_entries = Felt::try_from(num_changed_entries).expect(
                        "number of changed entries should not exceed max representable felt",
                    );

                    elements.extend_from_slice(&[
                        Self::DOMAIN_MAP,
                        num_changed_entries,
                        slot_id.suffix(),
                        slot_id.prefix(),
                    ]);
                    elements.extend_from_slice(EMPTY_WORD.as_elements());
                },
            }
        }
    }

}

impl Default for AccountStoragePatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Serializable for AccountStoragePatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let num_slots = u8::try_from(self.patches.len()).expect("number of slots should fit in u8");
        target.write_u8(num_slots);
        target.write_many(self.slots());
    }

    fn get_size_hint(&self) -> usize {
        let mut size = 0u8.get_size_hint();
        for (slot_name, slot_patch) in self.patches.iter() {
            size += slot_name.get_size_hint() + slot_patch.get_size_hint();
        }
        size
    }
}

impl Deserializable for AccountStoragePatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_slots = source.read_u8()? as usize;
        let entries = source
            .read_many_iter::<(StorageSlotName, StorageSlotPatch)>(num_slots)?
            .collect::<Result<Vec<_>, _>>()?;

        Self::from_entries(entries)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// STORAGE SLOT PATCH
// ================================================================================================

/// The patch of a single storage slot.
///
/// - [`StorageSlotPatch::Value`] carries the [`StorageValuePatch`] for a value slot.
/// - [`StorageSlotPatch::Map`] carries the [`StorageMapPatch`] for a map slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageSlotPatch {
    Value(StorageValuePatch),
    Map(StorageMapPatch),
}

impl StorageSlotPatch {
    // CONSTANTS
    // ----------------------------------------------------------------------------------------

    /// The type byte for value slot patches.
    const VALUE: u8 = 0;

    /// The type byte for map slot patches.
    const MAP: u8 = 1;

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

    // HELPERS
    // ----------------------------------------------------------------------------------------

    /// Merges `other` into `self`, with `other` taking precedence.
    ///
    /// # Errors
    ///
    /// Returns `None` if merging failed due to a slot type mismatch.
    fn merge(&mut self, slot_name: &StorageSlotName, other: Self) -> Result<(), AccountPatchError> {
        match (self, other) {
            (StorageSlotPatch::Value(current), StorageSlotPatch::Value(new)) => {
                current.merge(slot_name, new)
            },
            (StorageSlotPatch::Map(current), StorageSlotPatch::Map(new)) => {
                current.merge(slot_name, new)
            },
            (..) => Err(AccountPatchError::StorageSlotUsedAsDifferentTypes(slot_name.clone())),
        }
    }
}

impl From<StorageSlotContent> for StorageSlotPatch {
    /// Converts a slot's content into a [`StorageSlotPatch`] that creates the slot. Used when
    /// building a full state patch from an existing account.
    fn from(content: StorageSlotContent) -> Self {
        match content {
            StorageSlotContent::Value(value) => {
                StorageSlotPatch::Value(StorageValuePatch::Create { value })
            },
            StorageSlotContent::Map(storage_map) => {
                StorageSlotPatch::Map(StorageMapPatch::Create {
                    entries: StorageMapPatchEntries::from(storage_map),
                })
            },
        }
    }
}

impl Serializable for StorageSlotPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            StorageSlotPatch::Value(value_patch) => {
                target.write_u8(Self::VALUE);
                target.write(value_patch);
            },
            StorageSlotPatch::Map(map_patch) => {
                target.write_u8(Self::MAP);
                target.write(map_patch);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let tag_size = 0u8.get_size_hint();
        match self {
            StorageSlotPatch::Value(value_patch) => tag_size + value_patch.get_size_hint(),
            StorageSlotPatch::Map(map_patch) => tag_size + map_patch.get_size_hint(),
        }
    }
}

impl Deserializable for StorageSlotPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::VALUE => Ok(Self::Value(source.read()?)),
            Self::MAP => Ok(Self::Map(source.read()?)),
            other => Err(DeserializationError::InvalidValue(format!(
                "unknown storage slot patch variant {other}"
            ))),
        }
    }
}

// STORAGE VALUE PATCH
// ================================================================================================

/// The patch of a single value storage slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageValuePatch {
    /// Records the creation of the slot with the given value.
    Create { value: Word },

    /// Records that an existing slot was set to the given value.
    Update { value: Word },

    /// Records that the slot was removed.
    Remove,
}

impl StorageValuePatch {
    // CONSTANTS
    // ----------------------------------------------------------------------------------------

    const CREATE: u8 = 0;
    const UPDATE: u8 = 1;
    const REMOVE: u8 = 2;

    // ACCESSORS
    // ----------------------------------------------------------------------------------------

    /// Returns the new value of the slot for [`StorageValuePatch::Create`] and
    /// [`StorageValuePatch::Update`], or `None` for [`StorageValuePatch::Remove`].
    pub fn value(&self) -> Option<Word> {
        match self {
            StorageValuePatch::Create { value } | StorageValuePatch::Update { value } => {
                Some(*value)
            },
            StorageValuePatch::Remove => None,
        }
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------

    /// Returns the value to commit to.
    ///
    /// Slot removal commits to [`Word::empty`].
    fn committed_value(&self) -> Word {
        self.value().unwrap_or_default()
    }

    /// Merges `other` into `self`, with `other` taking precedence.
    ///
    /// A slot that was created and then updated remains created (with the updated value).
    fn merge(&mut self, slot_name: &StorageSlotName, other: Self) -> Result<(), AccountPatchError> {
        match (self, other) {
            // (Create, _) patterns
            // ------------------------------------------------------------------------------------
            (StorageValuePatch::Create { .. }, StorageValuePatch::Create { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeDoubleCreate(slot_name.clone()));
            },
            (
                StorageValuePatch::Create { value: current },
                StorageValuePatch::Update { value: incoming },
            ) => *current = incoming,
            (current @ StorageValuePatch::Create { .. }, StorageValuePatch::Remove) => {
                *current = StorageValuePatch::Remove
            },

            // (Update, _) patterns
            // ------------------------------------------------------------------------------------
            (StorageValuePatch::Update { .. }, StorageValuePatch::Create { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeCreateAfterUpdate(
                    slot_name.clone(),
                ));
            },
            (
                StorageValuePatch::Update { value: current },
                StorageValuePatch::Update { value: incoming },
            ) => *current = incoming,
            (current @ StorageValuePatch::Update { .. }, StorageValuePatch::Remove) => {
                *current = StorageValuePatch::Remove
            },

            // (Remove, _) patterns
            // ------------------------------------------------------------------------------------
            (current @ StorageValuePatch::Remove, incoming @ StorageValuePatch::Create { .. }) => {
                *current = incoming;
            },
            (StorageValuePatch::Remove, StorageValuePatch::Update { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeUpdateAfterRemove(
                    slot_name.clone(),
                ));
            },
            (StorageValuePatch::Remove, StorageValuePatch::Remove) => {
                return Err(AccountPatchError::StoragePatchMergeDoubleRemove(slot_name.clone()));
            },
        }

        Ok(())
    }
}

impl Serializable for StorageValuePatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            StorageValuePatch::Create { value } => {
                target.write_u8(Self::CREATE);
                target.write(value);
            },
            StorageValuePatch::Update { value } => {
                target.write_u8(Self::UPDATE);
                target.write(value);
            },
            StorageValuePatch::Remove => {
                target.write_u8(Self::REMOVE);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let tag_size = 0u8.get_size_hint();
        match self {
            StorageValuePatch::Create { .. } | StorageValuePatch::Update { .. } => {
                tag_size + Word::SERIALIZED_SIZE
            },
            StorageValuePatch::Remove => tag_size,
        }
    }
}

impl Deserializable for StorageValuePatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::CREATE => Ok(Self::Create { value: source.read()? }),
            Self::UPDATE => Ok(Self::Update { value: source.read()? }),
            Self::REMOVE => Ok(Self::Remove),
            other => Err(DeserializationError::InvalidValue(format!(
                "unknown storage value patch variant {other}"
            ))),
        }
    }
}

// STORAGE MAP PATCH
// ================================================================================================

/// The patch of a single map storage slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageMapPatch {
    /// Records the creation of the map with the given entries.
    ///
    /// An empty entry set is meaningful to represent the creation of an empty map.
    Create { entries: StorageMapPatchEntries },

    /// Records that the entries of an existing map were changed.
    Update { entries: StorageMapPatchEntries },

    /// Records that the map slot was removed.
    Remove,
}

impl StorageMapPatch {
    // CONSTANTS
    // ----------------------------------------------------------------------------------------

    const CREATE: u8 = 0;
    const UPDATE: u8 = 1;
    const REMOVE: u8 = 2;

    // ACCESSORS
    // ----------------------------------------------------------------------------------------

    /// Returns the entries of the map patch for [`StorageMapPatch::Create`] and
    /// [`StorageMapPatch::Update`], or `None` for [`StorageMapPatch::Remove`].
    pub fn entries(&self) -> Option<&StorageMapPatchEntries> {
        match self {
            StorageMapPatch::Create { entries } | StorageMapPatch::Update { entries } => {
                Some(entries)
            },
            StorageMapPatch::Remove => None,
        }
    }

    /// Consumes self and returns the entries of the map patch for [`StorageMapPatch::Create`] and
    /// [`StorageMapPatch::Update`], or `None` for [`StorageMapPatch::Remove`].
    pub fn into_entries(self) -> Option<StorageMapPatchEntries> {
        match self {
            StorageMapPatch::Create { entries } | StorageMapPatch::Update { entries } => {
                Some(entries)
            },
            StorageMapPatch::Remove => None,
        }
    }

    // HELPERS
    // ----------------------------------------------------------------------------------------

    /// Merges `other` into `self`, with `other` taking precedence.
    ///
    /// A map that was created and then updated remains created (with the merged entries).
    fn merge(&mut self, slot_name: &StorageSlotName, other: Self) -> Result<(), AccountPatchError> {
        match (self, other) {
            // (Create, _) patterns
            // ------------------------------------------------------------------------------------
            (StorageMapPatch::Create { .. }, StorageMapPatch::Create { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeDoubleCreate(slot_name.clone()));
            },
            (
                StorageMapPatch::Create { entries: current },
                StorageMapPatch::Update { entries: incoming },
            ) => current.merge(incoming),
            (current @ StorageMapPatch::Create { .. }, StorageMapPatch::Remove) => {
                *current = StorageMapPatch::Remove
            },

            // (Update, _) patterns
            // ------------------------------------------------------------------------------------
            (StorageMapPatch::Update { .. }, StorageMapPatch::Create { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeCreateAfterUpdate(
                    slot_name.clone(),
                ));
            },
            (
                StorageMapPatch::Update { entries: current },
                StorageMapPatch::Update { entries: incoming },
            ) => current.merge(incoming),
            (current @ StorageMapPatch::Update { .. }, StorageMapPatch::Remove) => {
                *current = StorageMapPatch::Remove
            },

            // (Remove, _) patterns
            // ------------------------------------------------------------------------------------
            (current @ StorageMapPatch::Remove, incoming @ StorageMapPatch::Create { .. }) => {
                *current = incoming;
            },
            (StorageMapPatch::Remove, StorageMapPatch::Update { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeUpdateAfterRemove(
                    slot_name.clone(),
                ));
            },
            (StorageMapPatch::Remove, StorageMapPatch::Remove) => {
                return Err(AccountPatchError::StoragePatchMergeDoubleRemove(slot_name.clone()));
            },
        }

        Ok(())
    }
}

impl Serializable for StorageMapPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            StorageMapPatch::Create { entries } => {
                target.write_u8(Self::CREATE);
                target.write(entries);
            },
            StorageMapPatch::Update { entries } => {
                target.write_u8(Self::UPDATE);
                target.write(entries);
            },
            StorageMapPatch::Remove => {
                target.write_u8(Self::REMOVE);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let tag_size = 0u8.get_size_hint();
        match self {
            StorageMapPatch::Create { entries } | StorageMapPatch::Update { entries } => {
                tag_size + entries.get_size_hint()
            },
            StorageMapPatch::Remove => tag_size,
        }
    }
}

impl Deserializable for StorageMapPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::CREATE => Ok(Self::Create { entries: source.read()? }),
            Self::UPDATE => Ok(Self::Update { entries: source.read()? }),
            Self::REMOVE => Ok(Self::Remove),
            other => Err(DeserializationError::InvalidValue(format!(
                "unknown storage map patch variant {other}"
            ))),
        }
    }
}

// STORAGE MAP PATCH ENTRIES
// ================================================================================================

/// The changed entries of a storage map, represented as a map of changed item key
/// ([`StorageMapKey`]) to value ([`Word`]). For cleared items the value is [`EMPTY_WORD`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageMapPatchEntries(BTreeMap<StorageMapKey, Word>);

impl StorageMapPatchEntries {
    /// Creates a new, empty set of map patch entries.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Creates a new set of map patch entries from the provided map.
    pub fn from_raw(entries: BTreeMap<StorageMapKey, Word>) -> Self {
        Self(entries)
    }

    /// Returns the number of changed entries.
    pub fn num_entries(&self) -> usize {
        self.0.len()
    }

    /// Returns a reference to the changed entries.
    ///
    /// Note that the returned key is the [`StorageMapKey`].
    pub fn as_map(&self) -> &BTreeMap<StorageMapKey, Word> {
        &self.0
    }

    /// Inserts an entry.
    pub fn insert(&mut self, key: StorageMapKey, value: Word) {
        self.0.insert(key, value);
    }

    /// Returns true if there are no changed entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Merges `other` into these entries, with the entries of `other` taking precedence.
    fn merge(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    /// Returns a mutable reference to the underlying map.
    pub fn as_map_mut(&mut self) -> &mut BTreeMap<StorageMapKey, Word> {
        &mut self.0
    }

    /// Consumes self and returns the underlying map.
    pub fn into_map(self) -> BTreeMap<StorageMapKey, Word> {
        self.0
    }
}

impl FromIterator<(StorageMapKey, Word)> for StorageMapPatchEntries {
    /// Creates a new set of map patch entries from the provided iterators of cleared and
    /// updated entries.
    fn from_iter<T: IntoIterator<Item = (StorageMapKey, Word)>>(iter: T) -> Self {
        Self::from_raw(BTreeMap::from_iter(iter))
    }
}

/// Converts a [`StorageMap`] into a set of map patch entries for full state patch construction.
impl From<StorageMap> for StorageMapPatchEntries {
    fn from(map: StorageMap) -> Self {
        StorageMapPatchEntries::from_raw(map.into_entries().into_iter().collect())
    }
}

impl Serializable for StorageMapPatchEntries {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.0.len());
        target.write_many(self.0.iter());
    }

    fn get_size_hint(&self) -> usize {
        self.0.len().get_size_hint()
            + self.0.len() * (StorageMapKey::SERIALIZED_SIZE + Word::SERIALIZED_SIZE)
    }
}

impl Deserializable for StorageMapPatchEntries {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_usize()?;
        let entries = source
            .read_many_iter::<(StorageMapKey, Word)>(count)?
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(Self::from_raw(entries))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use anyhow::Context;
    use assert_matches::assert_matches;

    use super::{
        AccountStoragePatch,
        Deserializable,
        Serializable,
        StorageMapPatch,
        StorageMapPatchEntries,
        StorageSlotPatch,
        StorageValuePatch,
    };
    use crate::account::{StorageMapKey, StorageSlotName};
    use crate::errors::AccountPatchError;
    use crate::{ONE, Word};

    #[test]
    fn account_storage_patch_accessors() {
        let value_slot = StorageSlotName::mock(1);
        let map_slot = StorageSlotName::mock(2);
        let absent_slot = StorageSlotName::mock(3);

        let value = Word::from([1u32, 2, 3, 4]);
        let map_key = StorageMapKey::from_array([10, 11, 12, 13]);
        let map_value = Word::from([5u32, 6, 7, 8]);
        let absent_key = StorageMapKey::from_array([99, 99, 99, 99]);

        let patch = AccountStoragePatch::from_iters(
            [],
            [(value_slot.clone(), value)],
            [(map_slot.clone(), StorageMapPatch::from_iters([], [(map_key, map_value)]))],
        );

        assert_eq!(patch.get_value(&value_slot), Some(value));
        assert_eq!(patch.get_value(&absent_slot), None);

        let map_patch = patch.get_map(&map_slot).unwrap();
        assert_eq!(map_patch.entries().unwrap().as_map().get(&map_key), Some(&map_value));
        assert_eq!(patch.get_map(&absent_slot), None);

        assert_eq!(patch.get_map_value(&map_slot, &map_key), Some(map_value));
        assert_eq!(patch.get_map_value(&map_slot, &absent_key), None);
        assert_eq!(patch.get_map_value(&absent_slot, &map_key), None);
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
            [(StorageSlotName::mock(3), StorageMapPatch::from_iters([], []))],
        );
        assert!(!storage_patch.is_empty());
    }

    #[test]
    fn account_storage_patch_deserialize_rejects_duplicate_slot() {
        let slot_name = StorageSlotName::mock(1);
        // Two value slot patches for the same slot name, length-prefixed with a count of 2.
        let mut bytes = Vec::new();
        bytes.push(2u8);
        let value_patch =
            StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::empty() });
        for _ in 0..2 {
            slot_name.write_into(&mut bytes);
            value_patch.write_into(&mut bytes);
        }

        let err = AccountStoragePatch::read_from_bytes(&bytes).unwrap_err();
        assert_matches!(err, super::DeserializationError::InvalidValue(_));
    }

    #[test]
    fn from_entries_rejects_duplicate_slot() {
        let slot_name = StorageSlotName::mock(1);
        let err = AccountStoragePatch::from_entries([
            (
                slot_name.clone(),
                StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::empty() }),
            ),
            (
                slot_name.clone(),
                StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::empty() }),
            ),
        ])
        .unwrap_err();
        assert_matches!(err, AccountPatchError::DuplicateStorageSlotName(name) => {
            assert_eq!(name, slot_name)
        });
    }

    #[test]
    fn test_serde_account_storage_patch() -> anyhow::Result<()> {
        for storage_patch in [
            AccountStoragePatch::new(),
            AccountStoragePatch::from_iters([StorageSlotName::mock(1)], [], []),
            AccountStoragePatch::from_iters(
                [],
                [(StorageSlotName::mock(2), Word::from([ONE, ONE, ONE, ONE]))],
                [],
            ),
            AccountStoragePatch::from_iters(
                [],
                [],
                [(StorageSlotName::mock(3), StorageMapPatch::from_iters([], []))],
            ),
        ] {
            let serialized = storage_patch.to_bytes();
            let deserialized = AccountStoragePatch::read_from_bytes(&serialized)?;
            assert_eq!(deserialized, storage_patch);
            assert_eq!(storage_patch.get_size_hint(), serialized.len());
        }

        Ok(())
    }

    #[test]
    fn test_serde_storage_value_patch() -> anyhow::Result<()> {
        for value_patch in [
            StorageValuePatch::Create { value: Word::from([1, 2, 3, 4u32]) },
            StorageValuePatch::Update { value: Word::from([1, 2, 3, 4u32]) },
            StorageValuePatch::Remove,
        ] {
            let slot_patch = StorageSlotPatch::Value(value_patch);
            let serialized = slot_patch.to_bytes();
            let deserialized = StorageSlotPatch::read_from_bytes(&serialized)?;
            assert_eq!(deserialized, slot_patch);
            assert_eq!(slot_patch.get_size_hint(), serialized.len());
        }

        Ok(())
    }

    #[test]
    fn test_serde_storage_map_patch() -> anyhow::Result<()> {
        let entries = StorageMapPatchEntries::from_iters(
            [StorageMapKey::from_array([1, 2, 3, 4])],
            [(StorageMapKey::from_array([5, 6, 7, 8]), Word::from([3, 4, 5, 6u32]))],
        );

        for map_patch in [
            StorageMapPatch::Create { entries: entries.clone() },
            StorageMapPatch::Update { entries },
            StorageMapPatch::Remove,
        ] {
            let slot_patch = StorageSlotPatch::Map(map_patch);
            let serialized = slot_patch.to_bytes();
            let deserialized = StorageSlotPatch::read_from_bytes(&serialized)?;
            assert_eq!(deserialized, slot_patch);
            assert_eq!(slot_patch.get_size_hint(), serialized.len());
        }

        Ok(())
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
            let value = item.map_or(Word::empty(), |value| Word::from([value, 0, 0, 0]));

            AccountStoragePatch::builder().update_value(slot_name, value).build()
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
    fn merge_maps(
        #[case] x: Option<u32>,
        #[case] y: Option<u32>,
        #[case] expected: Option<u32>,
    ) -> anyhow::Result<()> {
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

        patch_x.merge(&StorageSlotName::mock(5), patch_y)?;

        assert_eq!(patch_x, expected);

        Ok(())
    }
}
