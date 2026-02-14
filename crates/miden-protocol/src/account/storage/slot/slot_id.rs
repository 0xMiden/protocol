use core::cmp::Ordering;
use core::fmt::Display;
use core::hash::Hash;

use miden_core::field::PrimeField64;
use miden_core::utils::hash_string_to_word;

use crate::Felt;

/// The partial hash of a [`StorageSlotName`](super::StorageSlotName).
///
/// The ID of a slot are the third (`suffix`) and fourth (`prefix`) field elements of the
/// blake3-hashed slot name (i.e. word indices 2 and 3 in LE word order).
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
        let suffix = hashed_word[2];
        let prefix = hashed_word[3];
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
        le_bytes[..8].copy_from_slice(&self.suffix().as_canonical_u64().to_le_bytes());
        le_bytes[8..].copy_from_slice(&self.prefix().as_canonical_u64().to_le_bytes());
        u128::from_le_bytes(le_bytes)
    }
}

impl Ord for StorageSlotId {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.prefix.as_canonical_u64().cmp(&other.prefix.as_canonical_u64()) {
            ord @ Ordering::Less | ord @ Ordering::Greater => ord,
            Ordering::Equal => self.suffix.as_canonical_u64().cmp(&other.suffix.as_canonical_u64()),
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
        self.suffix.as_canonical_u64().hash(state);
        self.prefix.as_canonical_u64().hash(state);
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_id_as_u128() {
        let suffix = 5;
        let prefix = 3;
        let slot_id = StorageSlotId::new(
            Felt::new(u64::from(suffix as u32)),
            Felt::new(u64::from(prefix as u32)),
        );
        assert_eq!(slot_id.as_u128(), (prefix << 64) + suffix);
        assert_eq!(format!("{slot_id}"), "0x00000000000000030000000000000005");
    }
}
