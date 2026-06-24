use alloc::collections::BTreeMap;

use crate::Word;
use crate::account::{StorageMap, StorageMapKey, StorageSlotName};
use crate::errors::AccountPatchError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

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
    ///
    /// The entries should be non-empty, since empty entries are a no-op.
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
    pub(super) fn merge(
        &mut self,
        slot_name: &StorageSlotName,
        other: Self,
    ) -> Result<(), AccountPatchError> {
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
/// ([`StorageMapKey`]) to value ([`Word`]). For cleared items the value is [`Word::empty`].
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
    /// is always [`Word::empty`], only its key is written, saving [`Word::SERIALIZED_SIZE`] bytes
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
