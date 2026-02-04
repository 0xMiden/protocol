use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_core::{Felt, Word};

use crate::account::{
    AccountStorage,
    AccountStorageDelta,
    StorageMap,
    StorageMapDelta,
    StorageSlot,
    StorageSlotDelta,
    StorageSlotName,
};
use crate::note::NoteAssets;
use crate::utils::sync::LazyLock;

// ACCOUNT STORAGE DELTA
// ================================================================================================

impl AccountStorageDelta {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates an [`AccountStorageDelta`] from the given iterators.
    pub fn from_iters(
        cleared_values: impl IntoIterator<Item = StorageSlotName>,
        updated_values: impl IntoIterator<Item = (StorageSlotName, Word)>,
        updated_maps: impl IntoIterator<Item = (StorageSlotName, StorageMapDelta)>,
    ) -> Self {
        let deltas =
            cleared_values
                .into_iter()
                .map(|slot_name| (slot_name, StorageSlotDelta::with_empty_value()))
                .chain(updated_values.into_iter().map(|(slot_name, slot_value)| {
                    (slot_name, StorageSlotDelta::Value(slot_value))
                }))
                .chain(
                    updated_maps.into_iter().map(|(slot_name, map_delta)| {
                        (slot_name, StorageSlotDelta::Map(map_delta))
                    }),
                )
                .collect();

        Self::from_raw(deltas)
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
        items: impl IntoIterator<Item = (StorageSlotName, StorageMapDelta)>,
    ) -> Self {
        items.into_iter().for_each(|(slot_name, map_delta)| {
            for (key, value) in map_delta.entries() {
                self.set_map_item(slot_name.clone(), *key.inner(), *value).expect("TODO")
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

pub const STORAGE_VALUE_0: Word =
    Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
pub const STORAGE_VALUE_1: Word =
    Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
pub const STORAGE_LEAVES_2: [(Word, Word); 2] = [
    (
        Word::new([Felt::new(101), Felt::new(102), Felt::new(103), Felt::new(104)]),
        Word::new([Felt::new(1_u64), Felt::new(2_u64), Felt::new(3_u64), Felt::new(4_u64)]),
    ),
    (
        Word::new([Felt::new(105), Felt::new(106), Felt::new(107), Felt::new(108)]),
        Word::new([Felt::new(5_u64), Felt::new(6_u64), Felt::new(7_u64), Felt::new(8_u64)]),
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
        StorageMap::with_entries(STORAGE_LEAVES_2).unwrap()
    }
}

// UTILITIES
// --------------------------------------------------------------------------------------------

/// Returns a list of strings, one for each note asset.
pub fn prepare_assets(note_assets: &NoteAssets) -> Vec<String> {
    let mut assets = Vec::new();
    for &asset in note_assets.iter() {
        let asset_word = Word::from(asset);
        assets.push(asset_word.to_string());
    }
    assets
}
