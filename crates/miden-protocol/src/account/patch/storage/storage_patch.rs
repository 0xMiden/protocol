use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use super::slot_patch::MergeOutcome;
use crate::Felt;
use crate::account::{
    AccountStorage,
    StorageMapPatch,
    StorageSlotName,
    StorageSlotPatch,
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
    ///
    /// # Errors
    ///
    /// Returns an error if the number of patches exceeds
    /// [`AccountStorage::MAX_NUM_STORAGE_SLOTS`].
    pub fn from_raw(
        patches: BTreeMap<StorageSlotName, StorageSlotPatch>,
    ) -> Result<Self, AccountPatchError> {
        if patches.len() > AccountStorage::MAX_NUM_STORAGE_SLOTS {
            return Err(AccountPatchError::TooManyStorageSlotPatches(patches.len()));
        }

        Ok(Self { patches })
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

        Self::from_raw(patches)
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
    ///
    /// Each patch represents an atomic state change of account storage. This state change could be
    /// from a transaction, batch or block, as the latter two merge individual patches into a single
    /// one. Since the transaction is the lowest member in this hierarchy, the merge behavior is
    /// modelled so that whatever is valid (or invalid) to do in one transaction after another is
    /// also valid (or invalid) to merge.
    ///
    /// In general the operations have the following meaning:
    /// - `Create` takes the slot from absent to present.
    /// - `Update` requires the slot is present and updates it.
    /// - `Remove` takes the slot from present to absent.
    ///
    /// The nine permutations of `(current, incoming)` resolve as follows:
    ///
    /// - `(Create, Create)`: Errors because the second create assumes the slot is absent, but the
    ///   first already makes it present.
    /// - `(Create, Update)`: Merged to `Create`. The slot stays newly created, but carries the
    ///   updated value.
    /// - `(Create, Remove)`: Cancels out, so the slot patch is dropped entirely. A slot created and
    ///   then removed validly results in the slot being absent. This normalizes away such patches
    ///   and makes the patch not commit to a no-op (removing a slot that doesn't exist).
    /// - `(Update, Create)`: Errors because the create assumes the slot is absent, but the update
    ///   already requires it is present.
    /// - `(Update, Update)`: Merged to `Update`, keeping the latest value.
    /// - `(Update, Remove)`: Merged to `Remove`.
    /// - `(Remove, Create)`: Merged to `Create`. A slot removed and then re-created nets to a
    ///   (re-)creation carrying the new value. The resulting `Create` is applied to a base state
    ///   that still has the slot, so this re-creates an existing slot with the carried value.
    /// - `(Remove, Update)`: Errors because the update requires a present slot, but the remove left
    ///   it absent.
    /// - `(Remove, Remove)`: Errors because the second remove requires a present slot, but the
    ///   first already makes it absent.
    ///
    /// Value and map slots behave the same at the operation level, but map entries are merged
    /// entry-wise instead of being fully replaced.
    ///
    /// The error cases never occur when merging patches coming out of transactions or patches that
    /// were aggregated from transactions, as these are exactly the cases that would not be allowed
    /// by the transaction kernel. For instance, updating a slot in tx 2 when tx 1 removed it would
    /// be rejected in tx 2, since it would not exist.
    pub fn merge(&mut self, other: Self) -> Result<(), AccountPatchError> {
        for (slot_name, slot_patch) in other.patches {
            match self.patches.get_mut(&slot_name) {
                None => {
                    self.patches.insert(slot_name, slot_patch);
                },
                Some(existing) => {
                    if let MergeOutcome::Remove = existing.merge(&slot_name, slot_patch)? {
                        self.patches.remove(&slot_name);
                    }
                },
            }
        }

        if self.patches.len() > AccountStorage::MAX_NUM_STORAGE_SLOTS {
            return Err(AccountPatchError::TooManyStorageSlotPatches(self.patches.len()));
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
    pub(in crate::account) fn append_patch_elements(&self, elements: &mut Vec<Felt>) {
        for (slot_name, slot_patch) in self.patches.iter() {
            let slot_id = slot_name.id();

            match slot_patch {
                StorageSlotPatch::Value(value_patch) => {
                    elements.extend_from_slice(&[
                        Self::DOMAIN_VALUE,
                        Felt::from(value_patch.patch_op().as_u8()),
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

                    let omit_trailer =
                        map_patch.patch_op().is_update() && num_changed_entries == Felt::ZERO;
                    if !omit_trailer {
                        elements.extend_from_slice(&[
                            Self::DOMAIN_MAP,
                            Felt::from(map_patch.patch_op().as_u8()),
                            slot_id.suffix(),
                            slot_id.prefix(),
                        ]);
                        elements.extend_from_slice(&[
                            num_changed_entries,
                            Felt::ZERO,
                            Felt::ZERO,
                            Felt::ZERO,
                        ]);
                    }
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
