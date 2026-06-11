use alloc::vec::Vec;

use miden_core::{Felt, Word};

use crate::account::{
    AccountStorage,
    AccountStoragePatch,
    StorageMap,
    StorageMapKey,
    StorageMapPatch,
    StorageSlot,
    StorageSlotName,
    StorageSlotPatch,
};
use crate::utils::sync::LazyLock;

// ACCOUNT STORAGE PATCH
// ================================================================================================

impl AccountStoragePatch {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates an [`AccountStoragePatch`] from the given iterators.
    pub fn from_iters(
        cleared_values: impl IntoIterator<Item = StorageSlotName>,
        updated_values: impl IntoIterator<Item = (StorageSlotName, Word)>,
        updated_maps: impl IntoIterator<Item = (StorageSlotName, StorageMapPatch)>,
    ) -> Self {
        let deltas =
            cleared_values
                .into_iter()
                .map(|slot_name| (slot_name, StorageSlotPatch::with_empty_value()))
                .chain(updated_values.into_iter().map(|(slot_name, slot_value)| {
                    (slot_name, StorageSlotPatch::Value(slot_value))
                }))
                .chain(
                    updated_maps.into_iter().map(|(slot_name, map_patch)| {
                        (slot_name, StorageSlotPatch::Map(map_patch))
                    }),
                )
                .collect();

        Self::from_raw(deltas)
    }

    // ACCESSORS
    // -------------------------------------------------------------------------------------------

    /// Returns the updated value for the given slot, or `None` if the slot was not updated.
    ///
    /// # Panics
    /// Panics if the slot patch is a map.
    pub fn get_value(&self, slot_name: &StorageSlotName) -> Option<Word> {
        self.get(slot_name).cloned().map(StorageSlotPatch::unwrap_value)
    }

    /// Returns the map patch for the given slot, or `None` if the slot was not updated.
    ///
    /// # Panics
    /// Panics if the slot patch is a value.
    pub fn get_map(&self, slot_name: &StorageSlotName) -> Option<&StorageMapPatch> {
        self.get(slot_name).map(|patch| match patch {
            StorageSlotPatch::Map(map_patch) => map_patch,
            StorageSlotPatch::Value(_) => panic!("called get_map on a value slot patch"),
        })
    }

    /// Returns the updated value for the given map entry, or `None` if the slot or key was not
    /// updated.
    ///
    /// # Panics
    /// Panics if the slot patch is a value.
    pub fn get_map_value(&self, slot_name: &StorageSlotName, key: &StorageMapKey) -> Option<Word> {
        self.get_map(slot_name)?.entries().get(key).copied()
    }

    // MUTATORS
    // -------------------------------------------------------------------------------------------

    pub fn add_cleared_items(mut self, items: impl IntoIterator<Item = StorageSlotName>) -> Self {
        items
            .into_iter()
            .for_each(|slot_name| self.set_item(slot_name, Word::empty()).expect("TODO"));

        self
    }

    pub fn add_updated_values(
        mut self,
        items: impl IntoIterator<Item = (StorageSlotName, Word)>,
    ) -> Self {
        items.into_iter().for_each(|(slot_name, slot_value)| {
            self.set_item(slot_name, slot_value).expect("TODO")
        });

        self
    }

    pub fn add_updated_maps(
        mut self,
        items: impl IntoIterator<Item = (StorageSlotName, StorageMapPatch)>,
    ) -> Self {
        items.into_iter().for_each(|(slot_name, map_patch)| {
            for (key, value) in map_patch.entries() {
                self.set_map_item(slot_name.clone(), *key, *value).expect("TODO")
            }
        });

        self
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
