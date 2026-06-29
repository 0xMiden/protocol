use crate::account::{
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlotContent,
    StorageSlotName,
    StorageSlotType,
    StorageValuePatch,
};
use crate::errors::AccountPatchError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

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
    /// Returns whether the merged slot patch should be kept or removed because it cancels out (see
    /// [`MergeOutcome`]).
    ///
    /// # Errors
    ///
    /// Returns an error if merging failed due to a slot type mismatch.
    pub(super) fn merge(
        &mut self,
        slot_name: &StorageSlotName,
        other: Self,
    ) -> Result<MergeOutcome, AccountPatchError> {
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

// MERGE OUTCOME
// ================================================================================================

/// The outcome of merging one slot patch into another.
///
/// Merging can cause a slot patch to cancel out, in which case the parent
/// [`AccountStoragePatch`](crate::account::AccountStoragePatch) drops the slot patch rather than
/// commit to a no-op. This happens when a `Create` is followed by a `Remove`: the slot is taken
/// from absent to present and back to absent, so the base state is left unchanged.
pub(super) enum MergeOutcome {
    /// The merged slot patch should be kept.
    Keep,
    /// The merged slot patch cancels out and should be removed.
    Remove,
}
