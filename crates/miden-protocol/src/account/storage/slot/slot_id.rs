use core::cmp::Ordering;
use core::fmt::Display;
use core::hash::Hash;

use miden_core::utils::hash_string_to_word;

use crate::Felt;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// The partial hash of a [`StorageSlotName`](super::StorageSlotName).
///
/// The ID of a slot are the first (`suffix`) and second (`prefix`) field elements of the
/// blake3-hashed slot name.
///
/// The slot ID is used to uniquely identify a storage slot and is used to sort slots in account
/// storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageSlotId {
    suffix: Felt,
    prefix: Felt,
}

impl StorageSlotId {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`StorageSlotId`] from the provided felts.
    pub fn new(suffix: Felt, prefix: Felt) -> Self {
        Self { suffix, prefix }
    }

    /// Computes the [`StorageSlotId`] from a slot name.
    ///
    /// The provided `name`'s validity is **not** checked.
    pub(super) fn from_str(name: &str) -> StorageSlotId {
        let hashed_word = hash_string_to_word(name);
        let suffix = hashed_word[0];
        let prefix = hashed_word[1];
        StorageSlotId::new(suffix, prefix)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the suffix of the [`StorageSlotId`].
    pub fn suffix(&self) -> Felt {
        self.suffix
    }

    /// Returns the prefix of the [`StorageSlotId`].
    pub fn prefix(&self) -> Felt {
        self.prefix
    }

    /// Returns the [`StorageSlotId`]'s felts encoded into a u128.
    fn as_u128(&self) -> u128 {
        let mut le_bytes = [0_u8; 16];
        le_bytes[..8].copy_from_slice(&self.suffix().as_int().to_le_bytes());
        le_bytes[8..].copy_from_slice(&self.prefix().as_int().to_le_bytes());
        u128::from_le_bytes(le_bytes)
    }
}

impl Ord for StorageSlotId {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.prefix.as_int().cmp(&other.prefix.as_int()) {
            ord @ Ordering::Less | ord @ Ordering::Greater => ord,
            Ordering::Equal => self.suffix.as_int().cmp(&other.suffix.as_int()),
        }
    }
}

impl PartialOrd for StorageSlotId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for StorageSlotId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.suffix.inner().hash(state);
        self.prefix.inner().hash(state);
    }
}

impl Display for StorageSlotId {
    /// Returns a big-endian, hex-encoded string of length 34, including the `0x` prefix.
    ///
    /// This means it encodes 16 bytes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("0x{:032x}", self.as_u128()))
    }
}

impl Serializable for StorageSlotId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.suffix.write_into(target);
        self.prefix.write_into(target);
    }
}

impl Deserializable for StorageSlotId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let suffix = Felt::read_from(source)?;
        let prefix = Felt::read_from(source)?;
        Ok(StorageSlotId::new(suffix, prefix))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_id_as_u128() {
        let suffix = 5;
        let prefix = 3;
        let slot_id = StorageSlotId::new(Felt::from(suffix as u32), Felt::from(prefix as u32));
        assert_eq!(slot_id.as_u128(), (prefix << 64) + suffix);
        assert_eq!(format!("{slot_id}"), "0x00000000000000030000000000000005");
    }
}
