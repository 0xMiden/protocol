use alloc::string::ToString;
use alloc::vec::Vec;

use crate::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use crate::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use crate::{Felt, Hasher, WORD_SIZE, Word};

// VALIDATOR KEYS ERROR
// ================================================================================================

/// Error returned when constructing an invalid [`ValidatorKeys`] set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidatorKeysError {
    #[error("validator set must contain at least one key")]
    EmptySet,
    #[error(
        "validator set contains {count} keys but must contain at most {max}",
        max = ValidatorKeys::MAX,
    )]
    TooManyKeys { count: usize },
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
/// The number of validators is not fixed by the protocol: a chain may run with a single validator
/// and grow its validator set over time by rotating in a larger [`ValidatorKeys`] set (see
/// [`ProposedBlock::with_next_validator_keys`](crate::block::ProposedBlock::with_next_validator_keys)),
/// up to [`ValidatorKeys::MAX`] keys. The set holds at least one key, kept in a canonical order
/// (sorted by their serialized bytes) so that the [`ValidatorKeys::commitment`] is independent of
/// the order in which the keys were provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorKeys {
    /// Distinct validator public keys, sorted by their serialized bytes.
    keys: Vec<PublicKey>,
}

impl ValidatorKeys {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of validator keys in a set.
    pub const MAX: usize = 5;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`ValidatorKeys`] from the provided public keys.
    ///
    /// The keys are sorted into a canonical order by their serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `keys` is empty;
    /// - `keys` contains more than [`ValidatorKeys::MAX`] keys;
    /// - the set contains duplicate keys.
    pub fn new(mut keys: Vec<PublicKey>) -> Result<Self, ValidatorKeysError> {
        if keys.is_empty() {
            return Err(ValidatorKeysError::EmptySet);
        }
        if keys.len() > Self::MAX {
            return Err(ValidatorKeysError::TooManyKeys { count: keys.len() });
        }

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
    pub fn as_keys(&self) -> &[PublicKey] {
        &self.keys
    }

    /// Returns the number of validator keys in the set.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `false`, as a validator set always contains at least one key.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns a commitment to the validator set.
    ///
    /// The commitment is a sequential hash of the per-key commitments in canonical order, and is
    /// committed to by the [`BlockHeader`](crate::block::BlockHeader) as a single word. Since the
    /// hash covers every key, the commitment also implicitly binds the number of validators.
    pub fn commitment(&self) -> Word {
        let mut elements: Vec<Felt> = Vec::with_capacity(self.keys.len() * WORD_SIZE);
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
        let keys = Vec::<PublicKey>::read_from(source)?;
        Self::new(keys).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::random_secret_key::random_secret_key;

    fn random_keys(count: usize) -> Vec<PublicKey> {
        (0..count).map(|_| random_secret_key().public_key()).collect()
    }

    #[test]
    fn new_rejects_empty_set() {
        let result = ValidatorKeys::new(Vec::new());
        assert!(matches!(result, Err(ValidatorKeysError::EmptySet)));
    }

    #[test]
    fn new_accepts_single_validator() {
        let keys = ValidatorKeys::new(random_keys(1)).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn new_accepts_max_validators() {
        let keys = ValidatorKeys::new(random_keys(ValidatorKeys::MAX)).unwrap();
        assert_eq!(keys.len(), ValidatorKeys::MAX);
    }

    #[test]
    fn new_rejects_too_many_keys() {
        let result = ValidatorKeys::new(random_keys(ValidatorKeys::MAX + 1));
        assert!(matches!(
            result,
            Err(ValidatorKeysError::TooManyKeys { count }) if count == ValidatorKeys::MAX + 1
        ));
    }

    #[test]
    fn new_rejects_duplicate_keys() {
        let mut keys = random_keys(3);
        keys[1] = keys[0].clone();
        let result = ValidatorKeys::new(keys);
        assert!(matches!(result, Err(ValidatorKeysError::DuplicateKey)));
    }

    #[test]
    fn new_sorts_into_canonical_order() {
        let keys = random_keys(5);
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
        let validator_keys = ValidatorKeys::new(random_keys(4)).unwrap();
        let bytes = validator_keys.to_bytes();
        let deserialized = ValidatorKeys::read_from_bytes(&bytes).unwrap();
        assert_eq!(validator_keys, deserialized);
    }
}
