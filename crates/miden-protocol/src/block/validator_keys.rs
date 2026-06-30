use alloc::string::ToString;
use alloc::vec::Vec;

use crate::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

// VALIDATOR KEYS ERROR
// ================================================================================================

/// Error returned when constructing an invalid [`ValidatorKeys`] set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidatorKeysError {
    #[error("validator set contains duplicate public keys")]
    DuplicateKey,
}

// VALIDATOR KEYS
// ================================================================================================

/// The ordered set of validator public keys authorized to sign a block.
///
/// A block header commits to the [`ValidatorKeys`] authorized to sign the *next* block. A block's
/// signatures are verified positionally against the validator set committed to by its parent: the
/// signature in slot `i` is checked against the key at index `i` in this set.
///
/// The set always holds exactly [`ValidatorKeys::COUNT`] distinct keys, kept in a canonical order
/// (sorted by their serialized bytes) so that the [`ValidatorKeys::commitment`] is independent of
/// the order in which the keys were provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorKeys {
    /// Distinct validator public keys, sorted by their serialized bytes.
    keys: [PublicKey; ValidatorKeys::COUNT],
}

impl ValidatorKeys {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of validator keys in a set.
    pub const COUNT: usize = 5;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`ValidatorKeys`] from the provided [`ValidatorKeys::COUNT`] public keys.
    ///
    /// The keys are sorted into a canonical order by their serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the set contains duplicate keys.
    pub fn new(mut keys: [PublicKey; Self::COUNT]) -> Result<Self, ValidatorKeysError> {
        // Sort into a canonical order so the commitment is independent of input order.
        keys.sort_by_key(|key| key.to_bytes());

        // After sorting, duplicates are adjacent.
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ValidatorKeysError::DuplicateKey);
        }

        Ok(Self { keys })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the validator public keys in canonical order.
    pub fn as_keys(&self) -> &[PublicKey; Self::COUNT] {
        &self.keys
    }

    /// Returns the number of validator keys in the set, which is always [`ValidatorKeys::COUNT`].
    pub fn len(&self) -> usize {
        Self::COUNT
    }

    /// Returns `false`, as a validator set always contains [`ValidatorKeys::COUNT`] keys.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns a commitment to the validator set.
    ///
    /// The commitment is a sequential hash of the per-key commitments in canonical order, and is
    /// committed to by the [`BlockHeader`](crate::block::BlockHeader) as a single word.
    pub fn commitment(&self) -> Word {
        let mut elements: Vec<Felt> = Vec::new();
        for key in &self.keys {
            elements.extend_from_slice(key.to_commitment().as_elements());
        }
        Hasher::hash_elements(&elements)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ValidatorKeys {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.keys.write_into(target);
    }
}

impl Deserializable for ValidatorKeys {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let keys = <[PublicKey; Self::COUNT]>::read_from(source)?;
        Self::new(keys).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::random_secret_key::random_secret_key;

    fn random_keys() -> [PublicKey; ValidatorKeys::COUNT] {
        core::array::from_fn(|_| random_secret_key().public_key())
    }

    #[test]
    fn new_rejects_duplicate_keys() {
        let mut keys = random_keys();
        keys[1] = keys[0].clone();
        let result = ValidatorKeys::new(keys);
        assert!(matches!(result, Err(ValidatorKeysError::DuplicateKey)));
    }

    #[test]
    fn new_sorts_into_canonical_order() {
        let keys = random_keys();
        let forward = ValidatorKeys::new(keys.clone()).unwrap();

        let mut reversed = keys;
        reversed.reverse();
        let backward = ValidatorKeys::new(reversed).unwrap();

        // The canonical order makes the set and its commitment independent of input order.
        assert_eq!(forward.as_keys(), backward.as_keys());
        assert_eq!(forward.commitment(), backward.commitment());
    }

    #[test]
    fn serde_round_trip() {
        let validator_keys = ValidatorKeys::new(random_keys()).unwrap();
        let bytes = validator_keys.to_bytes();
        let deserialized = ValidatorKeys::read_from_bytes(&bytes).unwrap();
        assert_eq!(validator_keys, deserialized);
    }
}
