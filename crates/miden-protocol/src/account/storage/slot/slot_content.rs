use miden_core::EMPTY_WORD;

use crate::account::StorageSlotType;
use crate::account::storage::map::EMPTY_STORAGE_MAP_ROOT;
use crate::account::storage::{StorageMap, Word};

// STORAGE SLOT CONTENT
// ================================================================================================

/// Represents the contents of a [`StorageSlot`](super::StorageSlot).
///
/// The content of a storage slot can be of two types:
/// - A simple value which contains a single word (4 field elements or ~32 bytes).
/// - A key value map where both keys and values are words. The capacity of such storage slot is
///   theoretically unlimited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageSlotContent {
    Value(Word),
    Map(StorageMap),
}

impl StorageSlotContent {
    /// Returns true if this storage slot has a value equal to the default of its type.
    pub fn is_default(&self) -> bool {
        match self {
            StorageSlotContent::Value(value) => *value == EMPTY_WORD,
            StorageSlotContent::Map(map) => map.root() == EMPTY_STORAGE_MAP_ROOT,
        }
    }

    /// Returns the empty [Word] for a storage slot of this type
    pub fn default_word(&self) -> Word {
        match self {
            StorageSlotContent::Value(_) => EMPTY_WORD,
            StorageSlotContent::Map(_) => EMPTY_STORAGE_MAP_ROOT,
        }
    }

    /// Returns a [`StorageSlotContent::Value`] with an empty word.
    pub fn empty_value() -> Self {
        StorageSlotContent::Value(EMPTY_WORD)
    }

    /// Returns an empty [`StorageSlotContent::Map`].
    pub fn empty_map() -> Self {
        StorageSlotContent::Map(StorageMap::new())
    }

    /// Returns this storage slot value as a [Word]
    ///
    /// Returns:
    /// - For [`StorageSlotContent::Value`] the value.
    /// - For [`StorageSlotContent::Map`] the root of the [StorageMap].
    pub fn value(&self) -> Word {
        match self {
            Self::Value(value) => *value,
            Self::Map(map) => map.root(),
        }
    }

    /// Returns the type of this storage slot
    pub fn slot_type(&self) -> StorageSlotType {
        match self {
            StorageSlotContent::Value(_) => StorageSlotType::Value,
            StorageSlotContent::Map(_) => StorageSlotType::Map,
        }
    }
}
