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

    /// Returns a new [`AccountStoragePatchBuilder`] for ergonomically constructing a patch in tests.
    pub fn builder() -> AccountStoragePatchBuilder {
        AccountStoragePatchBuilder::new()
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
}

// ACCOUNT STORAGE PATCH BUILDER
// ================================================================================================

/// A builder for ergonomically constructing an [`AccountStoragePatch`] in test code.
///
/// Because it is meant for test code, the methods panic on misuse instead of returning errors:
/// - Value slots (and whole-slot removals) may be set only once.
/// - Map slots accumulate across calls, but a key may not be overwritten while it holds a non-empty
///   value. Overwriting a key whose current value is [`Word::empty`] (a cleared entry) is allowed.
#[derive(Clone, Debug, Default)]
pub struct AccountStoragePatchBuilder {
    patches: BTreeMap<StorageSlotName, StorageSlotPatch>,
}

impl AccountStoragePatchBuilder {
    /// Creates a new, empty builder.
    pub fn new() -> Self {
        Self { patches: BTreeMap::new() }
    }

    /// Records the creation of a value slot with the provided value.
    pub fn create_value(self, slot_name: StorageSlotName, value: Word) -> Self {
        self.set_unique_slot(slot_name, StorageSlotPatch::Value(StorageValuePatch::Create { value }))
    }

    /// Records the update of a value slot to the provided value.
    pub fn update_value(self, slot_name: StorageSlotName, value: Word) -> Self {
        self.set_unique_slot(slot_name, StorageSlotPatch::Value(StorageValuePatch::Update { value }))
    }

    /// Records the removal of a value slot.
    pub fn remove_value(self, slot_name: StorageSlotName) -> Self {
        self.set_unique_slot(slot_name, StorageSlotPatch::Value(StorageValuePatch::Remove))
    }

    /// Records the creation of a map slot with the provided entries.
    ///
    /// May be called repeatedly for the same slot to accumulate entries.
    pub fn create_map(
        self,
        slot_name: StorageSlotName,
        entries: impl IntoIterator<Item = (StorageMapKey, Word)>,
    ) -> Self {
        self.insert_map_entries(slot_name, true, entries)
    }

    /// Records the update of a map slot with the provided entries.
    ///
    /// May be called repeatedly for the same slot to accumulate entries.
    pub fn update_map(
        self,
        slot_name: StorageSlotName,
        entries: impl IntoIterator<Item = (StorageMapKey, Word)>,
    ) -> Self {
        self.insert_map_entries(slot_name, false, entries)
    }

    /// Records the removal of a map slot.
    pub fn remove_map(self, slot_name: StorageSlotName) -> Self {
        self.set_unique_slot(slot_name, StorageSlotPatch::Map(StorageMapPatch::Remove))
    }

    /// Consumes the builder and returns the assembled [`AccountStoragePatch`].
    pub fn build(self) -> AccountStoragePatch {
        AccountStoragePatch::from_raw(self.patches)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Inserts a slot patch that may be set only once, panicking if the slot name is already used.
    fn set_unique_slot(mut self, slot_name: StorageSlotName, patch: StorageSlotPatch) -> Self {
        if self.patches.insert(slot_name.clone(), patch).is_some() {
            panic!("storage slot `{slot_name}` was already set");
        }

        self
    }

    /// Inserts map entries into a created (`create == true`) or updated map slot, accumulating into
    /// any existing entries.
    ///
    /// # Panics
    ///
    /// Panics if the slot was already set as a different slot or map operation type, or if a key is
    /// already set to a non-empty value.
    fn insert_map_entries(
        mut self,
        slot_name: StorageSlotName,
        create: bool,
        entries: impl IntoIterator<Item = (StorageMapKey, Word)>,
    ) -> Self {
        let slot_patch = self.patches.entry(slot_name.clone()).or_insert_with(|| {
            let entries = StorageMapPatchEntries::new();
            let map_patch = if create {
                StorageMapPatch::Create { entries }
            } else {
                StorageMapPatch::Update { entries }
            };
            StorageSlotPatch::Map(map_patch)
        });

        let existing_entries = match slot_patch {
            StorageSlotPatch::Map(StorageMapPatch::Create { entries }) if create => entries,
            StorageSlotPatch::Map(StorageMapPatch::Update { entries }) if !create => entries,
            _ => panic!(
                "storage slot `{slot_name}` was already set as a different slot or map operation type"
            ),
        };

        for (key, value) in entries {
            if existing_entries.as_map().get(&key).is_some_and(|current| *current != Word::empty()) {
                panic!("map key `{key:?}` in storage slot `{slot_name}` was already set");
            }
            existing_entries.insert(key, value);
        }

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
