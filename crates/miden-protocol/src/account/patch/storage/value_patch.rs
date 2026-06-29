use super::slot_patch::MergeOutcome;
use crate::Word;
use crate::account::StorageSlotName;
use crate::errors::AccountPatchError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

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
    pub(super) fn committed_value(&self) -> Word {
        self.value().unwrap_or_default()
    }

    /// Maps a [`Word::empty`] value to `None` and any other value to `Some`, so that empty values
    /// serialize compactly as a single `None` tag instead of a full [`Word`].
    fn compact_value(value: &Word) -> Option<&Word> {
        (!value.is_empty()).then_some(value)
    }

    /// Merges `other` into `self`, with `other` taking precedence.
    ///
    /// A slot that was created and then updated remains created (with the updated value). A slot
    /// that was created and then removed cancels out, signalled via [`MergeOutcome::Remove`].
    pub(super) fn merge(
        &mut self,
        slot_name: &StorageSlotName,
        other: Self,
    ) -> Result<MergeOutcome, AccountPatchError> {
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
            (StorageValuePatch::Create { .. }, StorageValuePatch::Remove) => {
                return Ok(MergeOutcome::Remove);
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

        Ok(MergeOutcome::Keep)
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
