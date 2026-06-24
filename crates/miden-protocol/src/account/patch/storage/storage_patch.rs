use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::{StorageMapPatch, StorageSlotName, StorageSlotPatch, StorageValuePatch};
use crate::errors::AccountPatchError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word, ZERO};

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
                    elements.extend_from_slice(Word::empty().as_elements());
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
