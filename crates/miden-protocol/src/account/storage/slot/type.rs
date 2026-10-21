use alloc::string::ToString;
use core::fmt::Display;

use crate::Felt;
use crate::account::StorageArrayLength;
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
pub enum StorageSlotType {
    /// A single word.
    Value,
    /// A map commitment.
    Map,
    /// An array with its word count encoded in the slot type.
    Array(StorageArrayLength),
}

impl StorageSlotType {
    const VALUE_TYPE: u8 = 0;
    const MAP_TYPE: u8 = 1;
    const ARRAY_TYPE: u8 = 2;

    pub fn as_felt(&self) -> Felt {
        match self {
            Self::Value => Felt::from(Self::VALUE_TYPE),
            Self::Map => Felt::from(Self::MAP_TYPE),
            Self::Array(length) => Felt::new_unchecked(
                u64::from(Self::ARRAY_TYPE) + (u64::from(length.as_u16()) << 32),
            ),
        }
    }

    /// Words counted toward the account storage payload limit.
    pub fn num_words(&self) -> usize {
        match self {
            Self::Value | Self::Map => 1,
            Self::Array(length) => length.as_usize(),
        }
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
        let encoded = value.as_canonical_u64();
        match (encoded as u32, encoded >> 32) {
            (0, 0) => Ok(Self::Value),
            (1, 0) => Ok(Self::Map),
            (2, length) => Ok(Self::Array(StorageArrayLength::try_from(length as usize)?)),
            _ => Err(AccountError::other("invalid storage slot type")),
        }
    }
}

impl Display for StorageSlotType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageSlotType::Value => f.write_str("value"),
            StorageSlotType::Map => f.write_str("map"),
            StorageSlotType::Array(length) => write!(f, "array[{}]", length.as_u16()),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StorageSlotType {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Value => target.write_u8(Self::VALUE_TYPE),
            Self::Map => target.write_u8(Self::MAP_TYPE),
            Self::Array(length) => {
                target.write_u8(Self::ARRAY_TYPE);
                target.write(length);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        // The serialized size of a slot type.
        if matches!(self, Self::Array(_)) { 3 } else { 1 }
    }
}

impl Deserializable for StorageSlotType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let storage_slot_type = source.read_u8()?;

        match storage_slot_type {
            Self::VALUE_TYPE => Ok(Self::Value),
            Self::MAP_TYPE => Ok(Self::Map),
            Self::ARRAY_TYPE => Ok(Self::Array(source.read()?)),
            _ => Err(DeserializationError::InvalidValue(storage_slot_type.to_string())),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::Felt;
    use crate::account::{StorageArrayLength, StorageSlotType};
    use crate::utils::serde::{Deserializable, Serializable};

    #[test]
    fn test_serde_account_storage_slot_type() {
        for slot_type in [
            StorageSlotType::Value,
            StorageSlotType::Map,
            StorageSlotType::Array(StorageArrayLength::try_from(1).unwrap()),
            StorageSlotType::Array(StorageArrayLength::try_from(256).unwrap()),
        ] {
            let bytes = slot_type.to_bytes();
            assert_eq!(StorageSlotType::read_from_bytes(&bytes).unwrap(), slot_type);
        }
    }

    #[test]
    fn test_storage_slot_type_from_felt() {
        let felt = Felt::ZERO;
        let slot_type = StorageSlotType::try_from(felt).unwrap();
        assert_eq!(slot_type, StorageSlotType::Value);

        let felt = Felt::ONE;
        let slot_type = StorageSlotType::try_from(felt).unwrap();
        assert_eq!(slot_type, StorageSlotType::Map);

        for length in [1, 256] {
            let slot_type = StorageSlotType::Array(StorageArrayLength::try_from(length).unwrap());
            assert_eq!(StorageSlotType::try_from(slot_type.as_felt()).unwrap(), slot_type);
        }

        for invalid in [2, 2 + (257 << 32), 1 + (1 << 32), 3 + (1 << 32)] {
            assert!(StorageSlotType::try_from(Felt::new_unchecked(invalid)).is_err());
        }
    }
}
