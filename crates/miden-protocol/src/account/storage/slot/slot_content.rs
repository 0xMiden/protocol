use miden_core::EMPTY_WORD;

use crate::account::storage::map::EMPTY_STORAGE_MAP_ROOT;
use crate::account::storage::{StorageMap, Word};
use crate::account::{StorageArray, StorageSlotType};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// STORAGE SLOT CONTENT
// ================================================================================================

/// The value, array, or map stored in a [`StorageSlot`](super::StorageSlot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageSlotContent {
    Value(Word),
    Map(StorageMap),
    Array(StorageArray),
}

impl StorageSlotContent {
    /// Returns true if this storage slot has a value equal to the default of its type.
    pub fn is_default(&self) -> bool {
        match self {
            StorageSlotContent::Value(value) => *value == EMPTY_WORD,
            Self::Array(array) => array.values().iter().all(Word::is_empty),
            StorageSlotContent::Map(map) => map.root() == EMPTY_STORAGE_MAP_ROOT,
        }
    }

    /// Returns the empty [Word] for a storage slot of this type
    pub fn default_word(&self) -> Word {
        match self {
            StorageSlotContent::Value(_) => EMPTY_WORD,
            Self::Array(array) => StorageArray::empty(array.length()).commitment(),
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
    /// - For [`StorageSlotContent::Array`] the commitment to the ordered words.
    pub fn value(&self) -> Word {
        match self {
            Self::Value(value) => *value,
            Self::Array(array) => array.commitment(),
            Self::Map(map) => map.root(),
        }
    }

    /// Returns the type of this storage slot
    pub fn slot_type(&self) -> StorageSlotType {
        match self {
            StorageSlotContent::Value(_) => StorageSlotType::Value,
            Self::Array(array) => StorageSlotType::Array(array.length()),
            StorageSlotContent::Map(_) => StorageSlotType::Map,
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StorageSlotContent {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.slot_type());

        match self {
            Self::Value(value) => target.write(value),
            Self::Array(array) => target.write_many(array.values()),
            Self::Map(map) => target.write(map),
        }
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.slot_type().get_size_hint();

        size += match self {
            StorageSlotContent::Value(word) => word.get_size_hint(),
            Self::Array(array) => array.values().len() * Word::SERIALIZED_SIZE,
            StorageSlotContent::Map(storage_map) => storage_map.get_size_hint(),
        };

        size
    }
}

impl Deserializable for StorageSlotContent {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let storage_slot_type = source.read::<StorageSlotType>()?;

        match storage_slot_type {
            StorageSlotType::Array(length) => {
                let values = source.read_many_iter(length.as_usize())?.collect::<Result<_, _>>()?;
                Ok(Self::Array(StorageArray::new(values).expect("validated array length")))
            },
            StorageSlotType::Value => {
                let word = source.read::<Word>()?;
                Ok(StorageSlotContent::Value(word))
            },
            StorageSlotType::Map => {
                let map = source.read::<StorageMap>()?;
                Ok(StorageSlotContent::Map(map))
            },
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::account::AccountStorage;
    use crate::utils::serde::{Deserializable, Serializable};

    #[test]
    fn test_serde_storage_slot_content() {
        let storage = AccountStorage::mock();
        let serialized = storage.to_bytes();
        let deserialized = AccountStorage::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, storage)
    }
}
