use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_core::{Felt, Word};

use crate::account::{
    AccountStorage,
    AccountStoragePatch,
    StorageMap,
    StorageMapKey,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlot,
    StorageSlotName,
    StorageSlotPatch,
    StorageValuePatch,
};
use crate::utils::sync::LazyLock;

// ACCOUNT STORAGE PATCH
// ================================================================================================

impl AccountStoragePatch {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates an [`AccountStoragePatch`] of `Update` patches from the given iterators.
    ///
    /// Cleared and updated values are recorded as [`StorageValuePatch::Update`]; the provided map
    /// patches are stored as-is.
    pub fn from_iters(
        cleared_values: impl IntoIterator<Item = StorageSlotName>,
        updated_values: impl IntoIterator<Item = (StorageSlotName, Word)>,
        updated_maps: impl IntoIterator<Item = (StorageSlotName, StorageMapPatch)>,
    ) -> Self {
        let patches: BTreeMap<_, _> = cleared_values
            .into_iter()
            .map(|slot_name| {
                (
                    slot_name,
                    StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::empty() }),
                )
            })
            .chain(updated_values.into_iter().map(|(slot_name, value)| {
                (slot_name, StorageSlotPatch::Value(StorageValuePatch::Update { value }))
            }))
            .chain(
                updated_maps
                    .into_iter()
                    .map(|(slot_name, map_patch)| (slot_name, StorageSlotPatch::Map(map_patch))),
            )
            .collect();

        Self::from_raw(patches)
    }

    // ACCESSORS
    // -------------------------------------------------------------------------------------------

    /// Returns the value patched into the given slot, or `None` if the slot is absent, removed, or
    /// a map slot.
    pub fn get_value(&self, slot_name: &StorageSlotName) -> Option<Word> {
        match self.get(slot_name)? {
            StorageSlotPatch::Value(value_patch) => value_patch.value(),
            StorageSlotPatch::Map(_) => None,
        }
    }

    /// Returns the map patch for the given slot, or `None` if the slot is absent or a value slot.
    pub fn get_map(&self, slot_name: &StorageSlotName) -> Option<&StorageMapPatch> {
        match self.get(slot_name)? {
            StorageSlotPatch::Map(map_patch) => Some(map_patch),
            StorageSlotPatch::Value(_) => None,
        }
    }

    /// Returns the value patched for the given map entry, or `None` if the slot, key, or entries
    /// are absent.
    pub fn get_map_value(&self, slot_name: &StorageSlotName, key: &StorageMapKey) -> Option<Word> {
        self.get_map(slot_name)?.entries()?.as_map().get(key).copied()
    }

    // MUTATORS
    // -------------------------------------------------------------------------------------------

    pub fn add_cleared_items(mut self, items: impl IntoIterator<Item = StorageSlotName>) -> Self {
        items.into_iter().for_each(|slot_name| {
            self.update_value(slot_name, Word::empty())
                .expect("value slot patch should not collide with a map slot patch")
        });

        self
    }

    pub fn add_updated_values(
        mut self,
        items: impl IntoIterator<Item = (StorageSlotName, Word)>,
    ) -> Self {
        items.into_iter().for_each(|(slot_name, value)| {
            self.update_value(slot_name, value)
                .expect("value slot patch should not collide with a map slot patch")
        });

        self
    }

    pub fn add_updated_maps(
        mut self,
        items: impl IntoIterator<Item = (StorageSlotName, StorageMapPatch)>,
    ) -> Self {
        items.into_iter().for_each(|(slot_name, map_patch)| {
            if let Some(entries) = map_patch.entries() {
                for (key, value) in entries.as_map() {
                    self.update_map_item(slot_name.clone(), *key, *value)
                        .expect("map slot patch should not collide with a value slot patch")
                }
            }
        });

        self
    }
}

impl StorageMapPatch {
    /// Creates a new [`StorageMapPatch::Update`] from the provided iterators of cleared and updated
    /// entries.
    pub fn from_iters(
        cleared_keys: impl IntoIterator<Item = StorageMapKey>,
        updated_entries: impl IntoIterator<Item = (StorageMapKey, Word)>,
    ) -> Self {
        StorageMapPatch::Update {
            entries: StorageMapPatchEntries::from_iters(cleared_keys, updated_entries),
        }
    }
}

impl StorageMapPatchEntries {
    /// Creates a new set of map patch entries from the provided iterators of cleared and updated
    /// entries.
    pub fn from_iters(
        cleared_keys: impl IntoIterator<Item = StorageMapKey>,
        updated_entries: impl IntoIterator<Item = (StorageMapKey, Word)>,
    ) -> Self {
        Self::from_raw(BTreeMap::from_iter(
            cleared_keys.into_iter().map(|key| (key, Word::empty())).chain(updated_entries),
        ))
    }
}

// CONSTANTS
// ================================================================================================

pub static MOCK_VALUE_SLOT0: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::test::value0").expect("storage slot name should be valid")
});
pub static MOCK_VALUE_SLOT1: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::test::value1").expect("storage slot name should be valid")
});
pub static MOCK_MAP_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::test::map").expect("storage slot name should be valid")
});

pub const STORAGE_VALUE_0: Word = Word::new([
    Felt::ONE,
    Felt::new_unchecked(2),
    Felt::new_unchecked(3),
    Felt::new_unchecked(4),
]);
pub const STORAGE_VALUE_1: Word = Word::new([
    Felt::new_unchecked(5),
    Felt::new_unchecked(6),
    Felt::new_unchecked(7),
    Felt::new_unchecked(8),
]);
pub const STORAGE_LEAVES_2: [(Word, Word); 2] = [
    (
        Word::new([
            Felt::new_unchecked(101),
            Felt::new_unchecked(102),
            Felt::new_unchecked(103),
            Felt::new_unchecked(104),
        ]),
        Word::new([
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]),
    ),
    (
        Word::new([
            Felt::new_unchecked(105),
            Felt::new_unchecked(106),
            Felt::new_unchecked(107),
            Felt::new_unchecked(108),
        ]),
        Word::new([
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]),
    ),
];

impl AccountStorage {
    /// Create account storage.
    pub fn mock() -> Self {
        AccountStorage::new(Self::mock_storage_slots()).unwrap()
    }

    pub fn mock_storage_slots() -> Vec<StorageSlot> {
        vec![Self::mock_value_slot0(), Self::mock_value_slot1(), Self::mock_map_slot()]
    }

    pub fn mock_value_slot0() -> StorageSlot {
        StorageSlot::with_value(MOCK_VALUE_SLOT0.clone(), STORAGE_VALUE_0)
    }

    pub fn mock_value_slot1() -> StorageSlot {
        StorageSlot::with_value(MOCK_VALUE_SLOT1.clone(), STORAGE_VALUE_1)
    }

    pub fn mock_map_slot() -> StorageSlot {
        StorageSlot::with_map(MOCK_MAP_SLOT.clone(), Self::mock_map())
    }

    pub fn mock_map() -> StorageMap {
        StorageMap::with_entries(
            STORAGE_LEAVES_2.map(|(key, value)| (StorageMapKey::from_raw(key), value)),
        )
        .unwrap()
    }
}
