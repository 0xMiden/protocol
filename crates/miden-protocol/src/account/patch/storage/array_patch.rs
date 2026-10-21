use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use super::slot_patch::MergeOutcome;
use crate::Word;
use crate::account::{
    StorageArray,
    StorageArrayError,
    StorageArrayLength,
    StoragePatchOperation,
    StorageSlotName,
};
use crate::errors::AccountPatchError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// STORAGE ARRAY PATCH
// ================================================================================================

/// The patch of a single array storage slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageArrayPatch {
    /// Creates the array, including zero words.
    Create { array: StorageArray },
    /// Updates the specified indices. Empty updates are omitted from commitments.
    Update { entries: StorageArrayPatchEntries },
    /// Removes an array with the specified length.
    Remove { length: StorageArrayLength },
}

impl StorageArrayPatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    const CREATE: u8 = 0;
    const UPDATE: u8 = 1;
    const REMOVE: u8 = 2;

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the length of the array this patch operates on.
    pub fn length(&self) -> StorageArrayLength {
        match self {
            Self::Create { array } => array.length(),
            Self::Update { entries } => entries.length(),
            Self::Remove { length } => *length,
        }
    }

    /// Returns the [`StoragePatchOperation`] that this patch represents.
    pub fn patch_op(&self) -> StoragePatchOperation {
        match self {
            Self::Create { .. } => StoragePatchOperation::Create,
            Self::Update { .. } => StoragePatchOperation::Update,
            Self::Remove { .. } => StoragePatchOperation::Remove,
        }
    }

    /// Returns entries in ascending index order. Creates include all words; removes have none.
    pub fn entries(&self) -> impl Iterator<Item = (u16, Word)> + '_ {
        let (create, update) = match self {
            Self::Create { array } => (Some(array), None),
            Self::Update { entries } => (None, Some(entries)),
            Self::Remove { .. } => (None, None),
        };
        create
            .into_iter()
            .flat_map(|array| array.values().iter().enumerate().map(|(i, word)| (i as u16, *word)))
            .chain(
                update
                    .into_iter()
                    .flat_map(|entries| entries.entries.iter().map(|(i, word)| (*i, *word))),
            )
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Merges `other` into `self`, with `other` taking precedence.
    ///
    /// Array lengths must match unless a removed slot is being recreated.
    pub(super) fn merge(
        &mut self,
        slot_name: &StorageSlotName,
        other: Self,
    ) -> Result<MergeOutcome, AccountPatchError> {
        // Removing and recreating a slot can change its length.
        if !matches!((&self, &other), (Self::Remove { .. }, Self::Create { .. }))
            && self.length() != other.length()
        {
            return Err(StorageArrayError::LengthMismatch {
                expected: self.length().as_u16(),
                actual: other.length().as_u16(),
            }
            .into());
        }
        match (self, other) {
            (Self::Create { .. }, Self::Create { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeDoubleCreate(slot_name.clone()));
            },
            (Self::Create { array }, Self::Update { entries }) => *array = entries.apply(array)?,
            (Self::Create { .. }, Self::Remove { .. }) => return Ok(MergeOutcome::Remove),
            (Self::Update { .. }, Self::Create { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeCreateAfterUpdate(
                    slot_name.clone(),
                ));
            },
            (Self::Update { entries }, Self::Update { entries: incoming }) => {
                entries.entries.extend(incoming.entries)
            },
            (current @ Self::Update { .. }, incoming @ Self::Remove { .. })
            | (current @ Self::Remove { .. }, incoming @ Self::Create { .. }) => {
                *current = incoming
            },
            (Self::Remove { .. }, Self::Update { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeUpdateAfterRemove(
                    slot_name.clone(),
                ));
            },
            (Self::Remove { .. }, Self::Remove { .. }) => {
                return Err(AccountPatchError::StoragePatchMergeDoubleRemove(slot_name.clone()));
            },
        }
        Ok(MergeOutcome::Keep)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StorageArrayPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Create { array } => {
                target.write_u8(Self::CREATE);
                target.write(array);
            },
            Self::Update { entries } => {
                target.write_u8(Self::UPDATE);
                target.write(entries);
            },
            Self::Remove { length } => {
                target.write_u8(Self::REMOVE);
                target.write(length);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let tag_size = 0u8.get_size_hint();
        tag_size
            + match self {
                Self::Create { array } => array.get_size_hint(),
                Self::Update { entries } => entries.get_size_hint(),
                Self::Remove { length } => length.get_size_hint(),
            }
    }
}

impl Deserializable for StorageArrayPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::CREATE => Ok(Self::Create { array: source.read()? }),
            Self::UPDATE => Ok(Self::Update { entries: source.read()? }),
            Self::REMOVE => Ok(Self::Remove { length: source.read()? }),
            tag => Err(DeserializationError::InvalidValue(format!(
                "unknown array patch operation {tag}"
            ))),
        }
    }
}

// STORAGE ARRAY PATCH ENTRIES
// ================================================================================================

/// The changed words of an array, indexed by their positions in the array.
///
/// Zero words are retained because writing zero updates an element rather than removing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageArrayPatchEntries {
    length: StorageArrayLength,
    entries: BTreeMap<u16, Word>,
}

impl StorageArrayPatchEntries {
    /// Creates sparse updates for an array of the given length.
    ///
    /// # Errors
    ///
    /// Returns an error if an index is duplicated or is not less than `length`.
    pub fn new(
        length: StorageArrayLength,
        entries: impl IntoIterator<Item = (u16, Word)>,
    ) -> Result<Self, StorageArrayError> {
        let mut values = BTreeMap::new();
        for (index, value) in entries {
            if index >= length.as_u16() {
                return Err(StorageArrayError::IndexOutOfBounds { index, length: length.as_u16() });
            }
            if values.insert(index, value).is_some() {
                return Err(StorageArrayError::DuplicateIndex(index));
            }
        }
        Ok(Self { length, entries: values })
    }

    /// Finds changed words between arrays of equal length.
    ///
    /// # Errors
    ///
    /// Returns an error if the array lengths differ.
    pub fn between(
        initial: &StorageArray,
        final_array: &StorageArray,
    ) -> Result<Self, StorageArrayError> {
        if initial.length() != final_array.length() {
            return Err(StorageArrayError::LengthMismatch {
                expected: initial.length().as_u16(),
                actual: final_array.length().as_u16(),
            });
        }
        Self::new(
            initial.length(),
            initial
                .values()
                .iter()
                .zip(final_array.values())
                .enumerate()
                .filter_map(|(i, (old, new))| (old != new).then_some((i as u16, *new))),
        )
    }

    /// Returns the length of the array these updates apply to.
    pub fn length(&self) -> StorageArrayLength {
        self.length
    }

    /// Returns the changed entries in index order.
    pub fn as_map(&self) -> &BTreeMap<u16, Word> {
        &self.entries
    }

    /// Returns `true` if there are no changed entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Applies updates to an array of the same length.
    ///
    /// # Errors
    ///
    /// Returns an error if the array length differs from [`Self::length`].
    pub fn apply(&self, array: &StorageArray) -> Result<StorageArray, StorageArrayError> {
        if array.length() != self.length {
            return Err(StorageArrayError::LengthMismatch {
                expected: array.length().as_u16(),
                actual: self.length.as_u16(),
            });
        }
        let mut values = array.values().to_vec();
        for (&index, &value) in &self.entries {
            values[usize::from(index)] = value;
        }
        StorageArray::new(values)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StorageArrayPatchEntries {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.length);
        target.write_u16(self.entries.len() as u16);
        target.write_many(&self.entries);
    }

    fn get_size_hint(&self) -> usize {
        self.length.get_size_hint()
            + 0u16.get_size_hint()
            + self.entries.len() * (0u16.get_size_hint() + Word::SERIALIZED_SIZE)
    }
}

impl Deserializable for StorageArrayPatchEntries {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let length: StorageArrayLength = source.read()?;
        let count = source.read_u16()?;
        if count > length.as_u16() {
            return Err(DeserializationError::InvalidValue("too many array patch entries".into()));
        }
        let entries = source.read_many_iter(usize::from(count))?.collect::<Result<Vec<_>, _>>()?;
        Self::new(length, entries)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
