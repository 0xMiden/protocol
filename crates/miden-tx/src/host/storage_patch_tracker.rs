use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountStorageHeader,
    AccountStoragePatch,
    PartialAccount,
    StorageMapKey,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
};

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
#[derive(Debug, Clone)]
pub struct StoragePatchTracker {
    /// Flag indicating whether this patch is for a new account.
    is_account_new: bool,
    /// The _initial_ storage header of the native account against which the transaction is
    /// executed. This is only used to look up the initial values of storage _value_ slots, while
    /// the map slots are unused.
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
        let initial_storage_header = if account.is_new() {
            empty_storage_header_from_account(account)
        } else {
            account.storage().header().clone()
        };

        let mut storage_patch_tracker = Self {
            is_account_new: account.is_new(),
            storage_header: initial_storage_header,
            init_maps: BTreeMap::new(),
            patch: AccountStoragePatch::new(),
        };

        // Insert account storage into patch if it is new to match the kernel behavior.
        if account.is_new() {
            account.storage().header().slots().for_each(|slot_header| {
                match slot_header.slot_type() {
                    StorageSlotType::Value => {
                        // For new accounts, all values should be added to the patch, even empty
                        // words, so that the final patch includes the storage slot.
                        storage_patch_tracker
                            .set_item(slot_header.name().clone(), slot_header.value());
                    },
                    StorageSlotType::Map => {
                        let storage_map = account
                            .storage()
                            .maps()
                            .find(|map| map.root() == slot_header.value())
                            .expect("storage map should be present in partial storage");

                        // Make sure each map is represented by at least an empty storage map patch.
                        storage_patch_tracker
                            .patch
                            .insert_empty_map_patch(slot_header.name().clone());

                        storage_map.entries().for_each(|(key, value)| {
                            storage_patch_tracker.set_map_item(
                                slot_header.name().clone(),
                                *key,
                                Word::empty(),
                                *value,
                            );
                        });
                    },
                }
            });
        }

        storage_patch_tracker
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates a value slot.
    pub fn set_item(&mut self, slot_name: StorageSlotName, new_value: Word) {
        self.patch
            .set_item(slot_name, new_value)
            .expect("transaction kernel should not change slot types");
    }

    /// Updates a map slot.
    pub fn set_map_item(
        &mut self,
        slot_name: StorageSlotName,
        key: StorageMapKey,
        prev_value: Word,
        new_value: Word,
    ) {
        // Don't update the patch if the new value matches the old one.
        if prev_value != new_value {
            self.set_init_map_item(slot_name.clone(), key, prev_value);
            self.patch
                .set_map_item(slot_name, key, new_value)
                .expect("transaction kernel should not change slot types");
        }
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
        let slot_map = self.init_maps.entry(slot_name).or_default();
        slot_map.entry(key).or_insert(prev_value);
    }

    /// Normalizes the storage patch by:
    ///
    /// - removing entries for value slot updates whose new value is equal to the initial value at
    ///   the beginning of transaction execution.
    /// - removing entries for map slot updates where for a given key, the new value is equal to the
    ///   initial value at the beginning of transaction execution.
    fn normalize(self) -> AccountStoragePatch {
        let Self {
            is_account_new,
            storage_header,
            init_maps,
            patch,
        } = self;
        let mut patches = patch.into_map();

        patches.retain(|slot_name, slot_patch| {
            match slot_patch {
                StorageSlotPatch::Value(new_value) => {
                    // SAFETY: The header in the initial storage is the one from the account
                    // against which the transaction is executed, so accessing that slot name
                    // should be fine.
                    let slot_header = storage_header
                        .find_slot_header_by_name(slot_name)
                        .expect("slot name should exist");

                    // Only retain the value if the account is new or if it has changed.
                    // New accounts must contain all slots, even empty ones, to represent the full
                    // storage state.
                    is_account_new || *new_value != slot_header.value()
                },

                // On the key-value level: Keep only the key-value pairs whose new value is
                // different from the initial value.
                // On the map level: Keep only the maps that are non-empty after its key-value
                // pairs have been normalized, or if the account is new.
                StorageSlotPatch::Map(map_patch) => {
                    let init_map = init_maps.get(slot_name);

                    if let Some(init_map) = init_map {
                        map_patch.as_map_mut().retain(|key, new_value| {
                            let initial_value = init_map.get(key).expect(
                              "the initial value should be present for every value that was updated",
                            );
                            new_value != initial_value
                        });
                    }

                    // Only retain the map patch if the account is new or if it still contains
                    // values after normalization.
                    is_account_new || !map_patch.is_empty()
                },
            }
        });

        AccountStoragePatch::from_raw(patches)
    }
}

/// Creates empty slots of the same slot types as the to-be-created account.
fn empty_storage_header_from_account(account: &PartialAccount) -> AccountStorageHeader {
    let slots: Vec<StorageSlotHeader> = account
        .storage()
        .header()
        .slots()
        .map(|slot_header| match slot_header.slot_type() {
            StorageSlotType::Value => {
                StorageSlotHeader::with_empty_value(slot_header.name().clone())
            },
            StorageSlotType::Map => StorageSlotHeader::with_empty_map(slot_header.name().clone()),
        })
        .collect();

    AccountStorageHeader::new(slots).expect("storage header should be valid")
}
