use alloc::string::ToString;
use core::fmt::Display;

use miden_core::{ONE, ZERO};

use crate::Felt;
use crate::errors::AccountError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// STORAGE SLOT TYPE
// ================================================================================================

/// The type of a storage slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StorageSlotType {
    /// Represents a slot that contains a value.
    Value = Self::VALUE_TYPE,
    /// Represents a slot that contains a commitment to a map with key-value pairs.
    Map = Self::MAP_TYPE,
}

impl StorageSlotType {
    const VALUE_TYPE: u8 = 0;
    const MAP_TYPE: u8 = 1;

    pub fn as_felt(&self) -> Felt {
        Felt::from(*self as u8)
    }

    /// Returns `true` if the slot is a value slot, `false` otherwise.
    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value)
    }

    /// Returns `true` if the slot is a map slot, `false` otherwise.
    pub fn is_map(&self) -> bool {
        matches!(self, Self::Map)
    }
}

impl TryFrom<u8> for StorageSlotType {
    type Error = AccountError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::VALUE_TYPE => Ok(StorageSlotType::Value),
            Self::MAP_TYPE => Ok(StorageSlotType::Map),
            _ => Err(AccountError::other(format!("unsupported storage slot type {value}"))),
        }
    }
}

impl TryFrom<Felt> for StorageSlotType {
    type Error = AccountError;

    fn try_from(value: Felt) -> Result<Self, Self::Error> {
        if value == ZERO {
            Ok(StorageSlotType::Value)
        } else if value == ONE {
            Ok(StorageSlotType::Map)
        } else {
            Err(AccountError::other("invalid storage slot type"))
        }
    }
}

impl Display for StorageSlotType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageSlotType::Value => f.write_str("value"),
            StorageSlotType::Map => f.write_str("map"),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StorageSlotType {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Value => target.write_u8(0),
            Self::Map => target.write_u8(1),
        }
    }

    fn get_size_hint(&self) -> usize {
        // The serialized size of a slot type.
        0u8.get_size_hint()
    }
}

impl Deserializable for StorageSlotType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let storage_slot_type = source.read_u8()?;

        match storage_slot_type {
            Self::VALUE_TYPE => Ok(Self::Value),
            Self::MAP_TYPE => Ok(Self::Map),
            _ => Err(DeserializationError::InvalidValue(storage_slot_type.to_string())),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::utils::{Deserializable, Serializable};

    use crate::account::StorageSlotType;
    use crate::{Felt, FieldElement};

    #[test]
    fn test_serde_account_storage_slot_type() {
        let type_0 = StorageSlotType::Value;
        let type_1 = StorageSlotType::Value;
        let type_0_bytes = type_0.to_bytes();
        let type_1_bytes = type_1.to_bytes();
        let deserialized_0 = StorageSlotType::read_from_bytes(&type_0_bytes).unwrap();
        let deserialized_1 = StorageSlotType::read_from_bytes(&type_1_bytes).unwrap();
        assert_eq!(type_0, deserialized_0);
        assert_eq!(type_1, deserialized_1);
    }

    #[test]
    fn test_storage_slot_type_from_felt() {
        let felt = Felt::ZERO;
        let slot_type = StorageSlotType::try_from(felt).unwrap();
        assert_eq!(slot_type, StorageSlotType::Value);

        let felt = Felt::ONE;
        let slot_type = StorageSlotType::try_from(felt).unwrap();
        assert_eq!(slot_type, StorageSlotType::Map);
    }
}
