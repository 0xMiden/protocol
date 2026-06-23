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

    /// Maps a [`Word::empty`] value to `None` and any other value to `Some`, so that empty values
    /// serialize compactly as a single `None` tag instead of a full [`Word`].
    fn compact_value(value: &Word) -> Option<&Word> {
        (!value.is_empty()).then_some(value)
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
                target.write(Self::compact_value(value));
            },
            StorageValuePatch::Update { value } => {
                target.write_u8(Self::UPDATE);
                target.write(Self::compact_value(value));
            },
            StorageValuePatch::Remove => {
                target.write_u8(Self::REMOVE);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let tag_size = 0u8.get_size_hint();
        match self {
            StorageValuePatch::Create { value } | StorageValuePatch::Update { value } => {
                tag_size + Self::compact_value(value).get_size_hint()
            },
            StorageValuePatch::Remove => tag_size,
        }
    }
}

impl Deserializable for StorageValuePatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::CREATE => Ok(Self::Create {
                value: source.read::<Option<Word>>()?.unwrap_or_default(),
            }),
            Self::UPDATE => Ok(Self::Update {
                value: source.read::<Option<Word>>()?.unwrap_or_default(),
            }),
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

    /// Returns an iterator over the keys of the cleared entries, i.e. those whose value is
    /// [`Word::empty`].
    fn cleared_entries(&self) -> impl Iterator<Item = &StorageMapKey> + Clone {
        self.0.iter().filter(|(_, value)| value.is_empty()).map(|(key, _)| key)
    }

    /// Returns an iterator over the updated entries, i.e. those whose value is not [`Word::empty`].
    fn updated_entries(&self) -> impl Iterator<Item = (&StorageMapKey, &Word)> + Clone {
        self.0.iter().filter(|(_, value)| !value.is_empty())
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
    /// Serializes the cleared and updated entries separately. Because the value of a cleared entry
    /// is always [`EMPTY_WORD`], only its key is written, saving [`Word::SERIALIZED_SIZE`] bytes
    /// per cleared entry compared to writing the empty value.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.cleared_entries().count());
        target.write_many(self.cleared_entries());

        target.write_usize(self.updated_entries().count());
        target.write_many(self.updated_entries());
    }

    fn get_size_hint(&self) -> usize {
        let num_cleared = self.cleared_entries().count();
        let num_updated = self.updated_entries().count();

        num_cleared.get_size_hint()
            + num_cleared * StorageMapKey::SERIALIZED_SIZE
            + num_updated.get_size_hint()
            + num_updated * (StorageMapKey::SERIALIZED_SIZE + Word::SERIALIZED_SIZE)
    }
}

impl Deserializable for StorageMapPatchEntries {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut entries = BTreeMap::new();

        let num_cleared = source.read_usize()?;
        for key in source.read_many_iter::<StorageMapKey>(num_cleared)? {
            let key = key?;
            if entries.insert(key, Word::empty()).is_some() {
                return Err(DeserializationError::InvalidValue(format!(
                    "duplicate key {key} in storage map patch entries"
                )));
            }
        }

        let num_updated = source.read_usize()?;
        for entry in source.read_many_iter::<(StorageMapKey, Word)>(num_updated)? {
            let (key, value) = entry?;
            if entries.insert(key, value).is_some() {
                return Err(DeserializationError::InvalidValue(format!(
                    "duplicate key {key} in storage map patch entries"
                )));
            }
        }

        Ok(Self::from_raw(entries))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use std::string::ToString;
    use std::sync::LazyLock;

    use anyhow::Context;
    use assert_matches::assert_matches;

    use super::{
        AccountStoragePatch,
        ByteWriter,
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

    static TEST_MAP_ENTRIES: LazyLock<StorageMapPatchEntries> = LazyLock::new(|| {
        StorageMapPatchEntries::from_iters(
            [StorageMapKey::from_array([1, 2, 3, 4])],
            [(StorageMapKey::from_array([5, 6, 7, 8]), Word::from([3, 4, 5, 6u32]))],
        )
    });

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
    fn storage_map_patch_entries_deserialize_rejects_duplicate_key() {
        let key = StorageMapKey::from_array([1, 2, 3, 4]);
        let value = Word::from([5u32, 6, 7, 8]);

        // One cleared entry and one updated entry sharing the same key, each section
        // length-prefixed with a count of 1.
        let mut bytes = Vec::new();
        bytes.write_usize(1);
        key.write_into(&mut bytes);
        bytes.write_usize(1);
        (key, value).write_into(&mut bytes);

        let err = StorageMapPatchEntries::read_from_bytes(&bytes).unwrap_err();
        assert_matches!(err, super::DeserializationError::InvalidValue(err) => {
            assert!(err.contains("duplicate key"))
        });
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

    #[rstest::rstest]
    #[case::value_create(StorageSlotPatch::Value(StorageValuePatch::Create { value: Word::from([1, 2, 3, 4u32])}))]
    #[case::value_update(StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::from([1, 2, 3, 4u32])}))]
    #[case::value_remove(StorageSlotPatch::Value(StorageValuePatch::Remove))]
    #[case::map_create(StorageSlotPatch::Map(StorageMapPatch::Create { entries: TEST_MAP_ENTRIES.clone() }))]
    #[case::map_update(StorageSlotPatch::Map(StorageMapPatch::Update { entries: TEST_MAP_ENTRIES.clone() }))]
    #[case::map_remove(StorageSlotPatch::Map(StorageMapPatch::Remove))]
    fn test_serde_storage_patch(#[case] slot_patch: StorageSlotPatch) -> anyhow::Result<()> {
        let serialized = slot_patch.to_bytes();
        let deserialized = StorageSlotPatch::read_from_bytes(&serialized)?;
        assert_eq!(deserialized, slot_patch);
        assert_eq!(slot_patch.get_size_hint(), serialized.len());

        Ok(())
    }

    // MERGE
    // --------------------------------------------------------------------------------------------
    //
    // The merge logic is duplicated verbatim between value slots ([`StorageValuePatch::merge`]) and
    // map slots ([`StorageMapPatch::merge`]): the same 3x3 operation matrix and the same errors.
    // The tests below deduplicate along both axes:
    // - the delta-operation axis via the `#[case]` table (the nine current/incoming transitions),
    // - the slot-type axis via `#[values]` (every case is run against both value and map slots).

    static TEST_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| StorageSlotName::mock(7));

    /// The seed used to build the patch that is merged into. Distinct from [`INCOMING_SEED`] so
    /// that assertions can tell which patch's value won.
    const CURRENT_SEED: u32 = 1;

    /// The seed used to build the patch that is merged in. On every successful merge the incoming
    /// value wins, so the expected result is always built from this seed.
    const INCOMING_SEED: u32 = 2;

    /// A delta operation, abstracting over value and map slots which share the same set.
    #[derive(Clone, Copy, Debug)]
    enum Op {
        Create,
        Update,
        Remove,
    }

    /// The kind of slot a patch operates on.
    #[derive(Clone, Copy, Debug)]
    enum SlotType {
        Value,
        Map,
    }

    /// The expected outcome of merging two slot patches.
    enum Expected {
        /// The merge succeeds, leaving a slot patch with the given operation and the incoming
        /// value.
        Ok(Op),
        /// The merge fails with the error produced by the given variant constructor.
        Err(AccountPatchError),
    }

    /// Builds map entries holding a single value derived from `seed`.
    ///
    /// The key is fixed so that merging current and incoming entries collides on it, letting the
    /// incoming value win - this mirrors how a value slot replaces its value on merge and keeps the
    /// expected result identical across slot types.
    fn build_map_entries(seed: u32) -> StorageMapPatchEntries {
        StorageMapPatchEntries::from_iter([(
            StorageMapKey::from_array([1, 0, 0, 0]),
            Word::from([seed, 0, 0, 0]),
        )])
    }

    /// Builds a slot patch of the given type and operation, carrying a value derived from `seed`.
    fn build_slot_patch(slot_type: SlotType, op: Op, seed: u32) -> StorageSlotPatch {
        match slot_type {
            SlotType::Value => {
                let value = Word::from([seed, 0, 0, 0]);
                StorageSlotPatch::Value(match op {
                    Op::Create => StorageValuePatch::Create { value },
                    Op::Update => StorageValuePatch::Update { value },
                    Op::Remove => StorageValuePatch::Remove,
                })
            },
            SlotType::Map => StorageSlotPatch::Map(match op {
                Op::Create => StorageMapPatch::Create { entries: build_map_entries(seed) },
                Op::Update => StorageMapPatch::Update { entries: build_map_entries(seed) },
                Op::Remove => StorageMapPatch::Remove,
            }),
        }
    }

    /// Wraps a single slot patch in an [`AccountStoragePatch`].
    fn single_slot_patch(
        slot_name: StorageSlotName,
        patch: StorageSlotPatch,
    ) -> AccountStoragePatch {
        AccountStoragePatch::from_raw(BTreeMap::from([(slot_name, patch)]))
    }

    #[rstest::rstest]
    #[case::create_create(
        Op::Create,
        Op::Create,
        Expected::Err(AccountPatchError::StoragePatchMergeDoubleCreate(TEST_SLOT_NAME.clone()))
    )]
    #[case::create_update(Op::Create, Op::Update, Expected::Ok(Op::Create))]
    #[case::create_remove(Op::Create, Op::Remove, Expected::Ok(Op::Remove))]
    #[case::update_create(
        Op::Update,
        Op::Create,
        Expected::Err(AccountPatchError::StoragePatchMergeCreateAfterUpdate(TEST_SLOT_NAME.clone()))
    )]
    #[case::update_update(Op::Update, Op::Update, Expected::Ok(Op::Update))]
    #[case::update_remove(Op::Update, Op::Remove, Expected::Ok(Op::Remove))]
    #[case::remove_create(Op::Remove, Op::Create, Expected::Ok(Op::Create))]
    #[case::remove_update(
        Op::Remove,
        Op::Update,
        Expected::Err(AccountPatchError::StoragePatchMergeUpdateAfterRemove(TEST_SLOT_NAME.clone()))
    )]
    #[case::remove_remove(
        Op::Remove,
        Op::Remove,
        Expected::Err(AccountPatchError::StoragePatchMergeDoubleRemove(TEST_SLOT_NAME.clone()))
    )]
    #[test]
    fn merge_slot_patch(
        #[case] current: Op,
        #[case] incoming: Op,
        #[case] expected: Expected,
        #[values(SlotType::Value, SlotType::Map)] slot_type: SlotType,
    ) -> anyhow::Result<()> {
        let slot_name = TEST_SLOT_NAME.clone();

        let mut current_patch = single_slot_patch(
            slot_name.clone(),
            build_slot_patch(slot_type, current, CURRENT_SEED),
        );
        let incoming_patch = single_slot_patch(
            slot_name.clone(),
            build_slot_patch(slot_type, incoming, INCOMING_SEED),
        );

        let result = current_patch.merge(incoming_patch);

        match expected {
            Expected::Ok(resulting_op) => {
                result.context("merge should succeed")?;
                let expected_patch = build_slot_patch(slot_type, resulting_op, INCOMING_SEED);
                assert_eq!(current_patch.get(&slot_name), Some(&expected_patch));
            },
            Expected::Err(expected_err) => {
                let err = result.err().context("merge should fail")?;
                // `AccountPatchError` is not `PartialEq`, so compare the stringified error.
                assert_eq!(err.to_string(), expected_err.to_string());
            },
        }

        Ok(())
    }

    #[rstest::rstest]
    #[case::value_then_map(SlotType::Value, SlotType::Map)]
    #[case::map_then_value(SlotType::Map, SlotType::Value)]
    #[test]
    fn merge_slot_patch_rejects_type_mismatch(
        #[case] current: SlotType,
        #[case] incoming: SlotType,
    ) -> anyhow::Result<()> {
        let slot_name = TEST_SLOT_NAME.clone();

        let mut current_patch = single_slot_patch(
            slot_name.clone(),
            build_slot_patch(current, Op::Create, CURRENT_SEED),
        );
        let incoming_patch = single_slot_patch(
            slot_name.clone(),
            build_slot_patch(incoming, Op::Create, INCOMING_SEED),
        );

        let err = current_patch.merge(incoming_patch).err().context("merge should fail")?;
        assert_matches!(
            err,
            AccountPatchError::StorageSlotUsedAsDifferentTypes(name) => assert_eq!(name, slot_name)
        );

        Ok(())
    }

    #[test]
    fn merge_inserts_disjoint_slots() -> anyhow::Result<()> {
        let value_slot = StorageSlotName::mock(1);
        let map_slot = StorageSlotName::mock(2);

        let value_patch = build_slot_patch(SlotType::Value, Op::Create, CURRENT_SEED);
        let map_patch = build_slot_patch(SlotType::Map, Op::Create, INCOMING_SEED);

        let mut current_patch = single_slot_patch(value_slot.clone(), value_patch.clone());
        current_patch.merge(single_slot_patch(map_slot.clone(), map_patch.clone()))?;

        assert_eq!(current_patch.num_slots(), 2);
        assert_eq!(current_patch.get(&value_slot), Some(&value_patch));
        assert_eq!(current_patch.get(&map_slot), Some(&map_patch));

        Ok(())
    }

    #[test]
    fn merge_map_accumulates_entries() -> anyhow::Result<()> {
        let slot_name = StorageSlotName::mock(3);
        let shared_key = StorageMapKey::from_array([1, 0, 0, 0]);
        let current_only_key = StorageMapKey::from_array([2, 0, 0, 0]);
        let incoming_only_key = StorageMapKey::from_array([3, 0, 0, 0]);

        let incoming_shared_value = Word::from([20u32, 0, 0, 0]);
        let current_only_value = Word::from([11u32, 0, 0, 0]);
        let incoming_only_value = Word::from([21u32, 0, 0, 0]);

        let current_entries = StorageMapPatchEntries::from_iter([
            (shared_key, Word::from([10u32, 0, 0, 0])),
            (current_only_key, current_only_value),
        ]);
        let incoming_entries = StorageMapPatchEntries::from_iter([
            (shared_key, incoming_shared_value),
            (incoming_only_key, incoming_only_value),
        ]);

        let mut current_patch = single_slot_patch(
            slot_name.clone(),
            StorageSlotPatch::Map(StorageMapPatch::Update { entries: current_entries }),
        );
        let incoming_patch = single_slot_patch(
            slot_name.clone(),
            StorageSlotPatch::Map(StorageMapPatch::Update { entries: incoming_entries }),
        );

        current_patch.merge(incoming_patch)?;

        let merged = match current_patch.get(&slot_name) {
            Some(StorageSlotPatch::Map(StorageMapPatch::Update { entries })) => entries.as_map(),
            other => anyhow::bail!("expected an updated map slot, got {other:?}"),
        };

        assert_eq!(merged.len(), 3);
        // The incoming value wins on the shared key, disjoint keys from both sides are kept.
        assert_eq!(merged.get(&shared_key), Some(&incoming_shared_value));
        assert_eq!(merged.get(&current_only_key), Some(&current_only_value));
        assert_eq!(merged.get(&incoming_only_key), Some(&incoming_only_value));

        Ok(())
    }
}
