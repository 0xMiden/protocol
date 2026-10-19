use alloc::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountStorageHeader,
    AccountStoragePatch,
    PartialAccount,
    StorageArray,
    StorageArrayPatch,
    StorageArrayPatchEntries,
    StorageMapKey,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
    StorageValuePatch,
};

use crate::TransactionKernelError;

/// Tracks storage changes during transaction execution.
///
/// Initial values and arrays come from the [`AccountStorageHeader`]. Initial map values are
/// recorded on their first write, so the full maps need not be loaded.
///
/// New accounts produce full `Create` patches. Existing accounts retain only changes from their
/// initial state.
#[derive(Debug, Clone)]
pub struct StoragePatchTracker {
    /// Initial storage of the native account.
    storage_header: AccountStorageHeader,
    /// Initial map values, indexed by slot name and map key.
    init_maps: BTreeMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>,
    /// The account storage patch.
    patch: AccountStoragePatch,
    /// Latest array contents, compared with the initial header during normalization.
    current_arrays: BTreeMap<StorageSlotName, StorageArray>,
}

impl StoragePatchTracker {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Initializes the tracker, recording every slot of a new account as created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the account is new and its partial storage does not contain the storage map of every map
    ///   slot.
    pub fn new(account: &PartialAccount) -> Result<Self, TransactionKernelError> {
        let mut init_maps = BTreeMap::new();
        let mut patches = BTreeMap::new();

        // Record all slots in a new account as created.
        if account.is_new() {
            for slot_header in account.storage().header().slots() {
                match slot_header.slot_type() {
                    StorageSlotType::Array(_) => {
                        patches.insert(
                            slot_header.name().clone(),
                            StorageSlotPatch::Array(StorageArrayPatch::Create {
                                array: slot_header.array().expect("array slot header").clone(),
                            }),
                        );
                    },
                    StorageSlotType::Value => {
                        // For new accounts, all values are recorded as created, even empty words,
                        // so that the final patch includes the storage slot.
                        let prev_entry = patches.insert(
                            slot_header.name().clone(),
                            StorageSlotPatch::Value(StorageValuePatch::Create {
                                value: slot_header.value(),
                            }),
                        );
                        assert!(prev_entry.is_none(), "storage header should contain unique slots");
                    },
                    StorageSlotType::Map => {
                        let storage_map = account
                            .storage()
                            .maps()
                            .find(|map| map.root() == slot_header.value())
                            .ok_or_else(|| {
                                TransactionKernelError::NewAccountMissingStorageMap(
                                    slot_header.name().clone(),
                                )
                            })?;

                        let mut map_patch_entries = StorageMapPatchEntries::new();
                        storage_map.entries().for_each(|(key, value)| {
                            // Track the empty word as the initial value for all non-empty storage
                            // map items to preserve the invariant that all touched keys have an
                            // entry in this map.
                            set_init_map_item(
                                &mut init_maps,
                                slot_header.name().clone(),
                                *key,
                                Word::empty(),
                            );

                            map_patch_entries.insert(*key, *value);
                        });

                        // This will also track the map as created if it is empty, which is correct.
                        let prev_entry = patches.insert(
                            slot_header.name().clone(),
                            StorageSlotPatch::Map(StorageMapPatch::Create {
                                entries: map_patch_entries,
                            }),
                        );
                        assert!(prev_entry.is_none(), "storage header should contain unique slots");
                    },
                }
            }
        }

        Ok(Self {
            storage_header: account.storage().header().clone(),
            init_maps,
            current_arrays: BTreeMap::new(),
            // The patches are derived from the account's storage slots, which are bounded by
            // `AccountStorage::MAX_NUM_STORAGE_SLOTS`, so this cannot exceed the limit.
            patch: AccountStoragePatch::from_raw(patches)
                .expect("number of slot patches is bounded by the account's storage slots"),
        })
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Records the latest array contents.
    pub fn set_array(
        &mut self,
        slot_name: StorageSlotName,
        array: StorageArray,
    ) -> Result<(), TransactionKernelError> {
        let initial = self
            .storage_header
            .find_slot_header_by_name(&slot_name)
            .and_then(|slot| slot.array())
            .ok_or_else(|| {
                TransactionKernelError::other("array slot missing from initial storage")
            })?;
        if initial.length() != array.length() {
            return Err(TransactionKernelError::other("array write changed the slot length"));
        }
        self.current_arrays.insert(slot_name, array);
        Ok(())
    }

    /// Records a change to a value slot.
    ///
    /// This lets [`AccountStoragePatch::merge`] handle reconciling different delta operations, e.g.
    /// Create(X) + Update(Y) becomes Create(Y).
    pub fn set_item(
        &mut self,
        slot_name: StorageSlotName,
        new_value: Word,
    ) -> Result<(), TransactionKernelError> {
        let update_patch = AccountStoragePatch::from_raw(BTreeMap::from_iter([(
            slot_name,
            StorageSlotPatch::Value(StorageValuePatch::Update { value: new_value }),
        )]))
        .expect("single entry does not exceed max num entries");

        self.patch.merge(update_patch).map_err(|source| {
            TransactionKernelError::other_with_source("failed to set_item on patch", source)
        })?;

        Ok(())
    }

    /// Records a change to a map slot entry.
    ///
    /// This lets [`AccountStoragePatch::merge`] handle reconciling different delta operations, e.g.
    /// Create(X) + Update(Y) becomes Create(Y).
    pub fn set_map_item(
        &mut self,
        slot_name: StorageSlotName,
        key: StorageMapKey,
        prev_value: Word,
        new_value: Word,
    ) -> Result<(), TransactionKernelError> {
        // Don't update the patch if the new value matches the old one.
        if prev_value != new_value {
            set_init_map_item(&mut self.init_maps, slot_name.clone(), key, prev_value);

            let update_patch = AccountStoragePatch::from_raw(BTreeMap::from_iter([(
                slot_name,
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_iter([(key, new_value)]),
                }),
            )]))
            .expect("single entry does not exceed max num entries");

            self.patch.merge(update_patch).map_err(|source| {
                TransactionKernelError::other_with_source("failed to set_map_item on patch", source)
            })?;
        }

        Ok(())
    }

    /// Consumes `self` and returns the resulting, normalized [`AccountStoragePatch`].
    pub fn into_patch(self) -> AccountStoragePatch {
        self.normalize()
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Builds sparse updates relative to initial storage, preserving `Create` and `Remove` patches.
    fn normalize(self) -> AccountStoragePatch {
        let Self {
            storage_header,
            init_maps,
            patch,
            current_arrays,
        } = self;
        let mut patches = patch.into_map();

        patches.retain(|slot_name, slot_patch| match slot_patch {
            StorageSlotPatch::Array(_) => true,
            StorageSlotPatch::Value(value_patch) => match value_patch {
                // Created and removed slots are always retained.
                StorageValuePatch::Create { .. } | StorageValuePatch::Remove => true,
                StorageValuePatch::Update { value } => {
                    // SAFETY: The header in the initial storage is the one from the account
                    // against which the transaction is executed, so accessing that slot name
                    // should be fine.
                    let slot_header = storage_header
                        .find_slot_header_by_name(slot_name)
                        .expect("slot name should exist");

                    *value != slot_header.value()
                },
            },

            StorageSlotPatch::Map(map_patch) => match map_patch {
              StorageMapPatch::Create { entries } => {
                // Values of a new map are empty by default, so we can normalize empty words
                // away.
                entries.as_map_mut().retain(|_key, value| {
                  !value.is_empty()
                });

                  // Created slots are always retained.
                  true
                },
                // Removed slots are always retained.
                StorageMapPatch::Remove => true,
                StorageMapPatch::Update { entries } => {
                    // On the key-value level: keep only the key-value pairs whose new value is
                    // different from the initial value.
                    if let Some(init_map) = init_maps.get(slot_name) {
                        entries.as_map_mut().retain(|key, new_value| {
                            let initial_value = init_map.get(key).expect(
                                "the initial value should be present for every value that was updated",
                            );
                            new_value != initial_value
                        });
                    }

                    // On the map level: keep only the maps that are non-empty after their
                    // key-value pairs have been normalized.
                    !entries.is_empty()
                },
            },
        });

        for (slot_name, array) in current_arrays {
            let patch = if patches.get(&slot_name).is_some_and(|patch| patch.patch_op().is_create())
            {
                StorageArrayPatch::Create { array }
            } else {
                let initial = storage_header
                    .find_slot_header_by_name(&slot_name)
                    .and_then(|slot| slot.array())
                    .expect("validated array slot");
                let entries = StorageArrayPatchEntries::between(initial, &array)
                    .expect("validated array length");
                if entries.is_empty() {
                    continue;
                }
                StorageArrayPatch::Update { entries }
            };
            patches.insert(slot_name, StorageSlotPatch::Array(patch));
        }

        // Every patch names a slot in the initial account, so the count stays within its bound.
        AccountStoragePatch::from_raw(patches)
            .expect("slot patches are bounded by the initial account storage")
    }
}

/// Sets the initial value of the given key in the given slot to the given value, if no value is
/// already tracked for that key.
fn set_init_map_item(
    init_maps: &mut BTreeMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>,
    slot_name: StorageSlotName,
    key: StorageMapKey,
    prev_value: Word,
) {
    let slot_map = init_maps.entry(slot_name).or_default();
    slot_map.entry(key).or_insert(prev_value);
}
