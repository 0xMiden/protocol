use alloc::collections::BTreeMap;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountStorageHeader,
    AccountStoragePatch,
    PartialAccount,
    StorageMapKey,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
    StorageValuePatch,
};

use crate::TransactionKernelError;

/// Keeps track of the initial storage of an account during transaction execution.
///
/// For storage value slots this can be simply inspected by looking in to the
/// [`AccountStorageHeader`].
///
/// For map slots, to avoid making a copy of the entire storage map or even requiring that it is
/// fully accessible in the first place, the initial values are tracked lazily. That is, whenever
/// `set_map_item` is called, the previous value is extracted from the stack and if that is the
/// first time the key is written to, then the previous value is the initial value of that key in
/// that slot.
///
/// For a new account, every slot is recorded as a [`StorageValuePatch::Create`] /
/// [`StorageMapPatch::Create`], which represents the account's full storage state. For an existing
/// account, changes are recorded as `Update` patches and no-op updates are normalized away.
#[derive(Debug, Clone)]
pub struct StoragePatchTracker {
    /// The _initial_ storage header of the native account against which the transaction is
    /// executed. This is only used to look up the initial values of storage _value_ slots when
    /// normalizing `Update` patches, while the map slots are unused.
    storage_header: AccountStorageHeader,
    /// A map from slot name to a map of key-value pairs where the key is a storage map key and
    /// the value represents the value of that key at the beginning of transaction execution.
    init_maps: BTreeMap<StorageSlotName, BTreeMap<StorageMapKey, Word>>,
    /// The account storage patch.
    patch: AccountStoragePatch,
}

impl StoragePatchTracker {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new initial storage patch from the provided account.
    ///
    /// If the account is new, inserts the storage entries into the patch analogously to the
    /// transaction kernel patch.
    pub fn new(account: &PartialAccount) -> Self {
        let mut init_maps = BTreeMap::new();
        let mut patches = BTreeMap::new();

        // Record all slots in a new account as created.
        if account.is_new() {
            account.storage().header().slots().for_each(|slot_header| {
                match slot_header.slot_type() {
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
                            .expect("storage map should be present in partial storage");

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
            });
        }

        Self {
            storage_header: account.storage().header().clone(),
            init_maps,
            patch: AccountStoragePatch::from_raw(patches),
        }
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

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
        )]));

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
            self.set_init_map_item(slot_name.clone(), key, prev_value);

            let update_patch = AccountStoragePatch::from_raw(BTreeMap::from_iter([(
                slot_name,
                StorageSlotPatch::Map(StorageMapPatch::Update {
                    entries: StorageMapPatchEntries::from_iter([(key, new_value)]),
                }),
            )]));

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

    /// Sets the initial value of the given key in the given slot to the given value, if no value is
    /// already tracked for that key.
    fn set_init_map_item(
        &mut self,
        slot_name: StorageSlotName,
        key: StorageMapKey,
        prev_value: Word,
    ) {
        set_init_map_item(&mut self.init_maps, slot_name, key, prev_value)
    }

    /// Normalizes the storage patch.
    ///
    /// `Create` patches are always retained, since they represent the full storage state of a new
    /// account. `Update` patches are retained only if they actually change the initial state:
    ///
    /// - value slot updates whose new value equals the initial value are removed.
    /// - map slot updates drop the entries whose new value equals the initial value, and the map
    ///   update itself is dropped if it has no entries left afterwards.
    fn normalize(self) -> AccountStoragePatch {
        let Self { storage_header, init_maps, patch, .. } = self;
        let mut patches = patch.into_map();

        patches.retain(|slot_name, slot_patch| match slot_patch {
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
                // Created and removed slots are always retained.
                StorageMapPatch::Create { .. } | StorageMapPatch::Remove => true,
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

        AccountStoragePatch::from_raw(patches)
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
