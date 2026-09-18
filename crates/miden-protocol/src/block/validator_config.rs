use alloc::string::ToString;
use alloc::vec::Vec;

use crate::crypto::SequentialCommit;
use crate::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use crate::errors::ValidatorConfigError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, WORD_SIZE, Word, ZERO};

// VALIDATOR CONFIG
// ================================================================================================

/// The ordered set of validator public keys authorized to sign a block, and how many of them must
/// sign.
///
/// The protocol does not support partial signing yet, so the quorum must be equal to the number of
/// keys. The quorum stays a separate field because the block header commits to it. Thus a smaller
/// quorum can be added later without a change to the shape of the commitment.
///
/// A block header commits to the [`ValidatorConfig`] authorized to sign the *next* block. A block's
/// signatures are verified positionally against the validator set committed to by its parent: the
/// signature in slot `i` is checked against the key at index `i` in this set.
///
/// The number of validators is not fixed by the protocol: a chain may run with a single validator
/// and grow its validator set over time by rotating in a larger [`ValidatorConfig`] (see
/// [`ProposedBlock::with_next_validator_config`](crate::block::ProposedBlock::with_next_validator_config)),
/// up to [`ValidatorConfig::MAX_VALIDATORS`] keys. The set holds at least one key, kept in a
/// canonical order (sorted by their serialized bytes) so that the commitment is independent of the
/// order in which the keys were provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorConfig {
    /// Distinct validator public keys, sorted by their serialized bytes.
    keys: Vec<PublicKey>,

    /// The number of validators that must sign a block for it to be valid.
    quorum: u16,
}

impl ValidatorConfig {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of validator keys in a set.
    pub const MAX_VALIDATORS: usize = 5;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`ValidatorConfig`] from the provided public keys and quorum.
    ///
    /// The keys are sorted into a canonical order by their serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `keys` is empty;
    /// - `keys` contains more than [`ValidatorConfig::MAX_VALIDATORS`] keys;
    /// - the set contains duplicate keys;
    /// - `quorum` does not equal the number of keys.
    pub fn new(mut keys: Vec<PublicKey>, quorum: u16) -> Result<Self, ValidatorConfigError> {
        if keys.is_empty() {
            return Err(ValidatorConfigError::EmptySet);
        }
        if keys.len() > Self::MAX_VALIDATORS {
            return Err(ValidatorConfigError::TooManyKeys { count: keys.len() });
        }
        if usize::from(quorum) != keys.len() {
            return Err(ValidatorConfigError::QuorumMustEqualValidatorCount {
                quorum,
                count: keys.len(),
            });
        }

        // Sort into a canonical order so the commitment is independent of input order.
        keys.sort_by_key(|key| key.to_bytes());

        // After sorting, duplicates are adjacent.
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ValidatorConfigError::DuplicateKey);
        }

        Ok(Self { keys, quorum })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the validator public keys in canonical order.
    pub fn keys(&self) -> &[PublicKey] {
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

    /// Returns the number of validators that must sign a block for it to be valid.
    pub fn quorum(&self) -> u16 {
        self.quorum
    }

    /// Returns a commitment to the validator configuration.
    ///
    /// It is committed to by the [`BlockHeader`](crate::block::BlockHeader) as a single word. Since
    /// the preimage covers every key, the commitment also implicitly binds the number of
    /// validators.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the preimage of [`ValidatorConfig::to_commitment`] as a sequence of field elements.
    ///
    /// The element layout is:
    ///
    /// ```text
    /// [[quorum, 0, 0, 0], KEY_COMMITMENT_0, KEY_COMMITMENT_1, ..., KEY_COMMITMENT_N]
    /// ```
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }
}

impl SequentialCommit for ValidatorConfig {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let mut elements: Vec<Felt> = Vec::with_capacity((self.keys.len() + 1) * WORD_SIZE);
        elements.extend([Felt::from(self.quorum), ZERO, ZERO, ZERO]);

        for key in &self.keys {
            elements.extend_from_slice(key.to_commitment().as_elements());
        }

        elements
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ValidatorConfig {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { keys, quorum } = self;

        let num_keys =
            u8::try_from(keys.len()).expect("constructor should validate num keys fits in u8");

        quorum.write_into(target);
        num_keys.write_into(target);
        target.write_many(keys);
    }
}

impl Deserializable for ValidatorConfig {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let quorum = u16::read_from(source)?;
        let num_keys: u8 = source.read()?;
        let keys = source
            .read_many_iter(num_keys as usize)?
            .collect::<Result<Vec<PublicKey>, _>>()?;

        Self::new(keys, quorum).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::testing::random_secret_key::random_secret_key;

    fn random_keys(count: usize) -> Vec<PublicKey> {
        (0..count).map(|_| random_secret_key().public_key()).collect()
    }

    #[test]
    fn new_rejects_empty_set() {
        let result = ValidatorConfig::new(Vec::new(), 1);
        assert_matches!(result, Err(ValidatorConfigError::EmptySet));
    }

    #[test]
    fn new_accepts_single_validator() -> anyhow::Result<()> {
        let config = ValidatorConfig::new(random_keys(1), 1)?;
        assert_eq!(config.len(), 1);
        assert_eq!(config.quorum(), 1);
        Ok(())
    }

    #[test]
    fn new_accepts_max_validators() -> anyhow::Result<()> {
        let max_validators = ValidatorConfig::MAX_VALIDATORS;
        let config = ValidatorConfig::new(random_keys(max_validators), max_validators as u16)?;
        assert_eq!(config.len(), max_validators);
        Ok(())
    }

    #[test]
    fn new_rejects_too_many_keys() {
        let result = ValidatorConfig::new(random_keys(ValidatorConfig::MAX_VALIDATORS + 1), 1);
        assert_matches!(
            result,
            Err(ValidatorConfigError::TooManyKeys { count }) if count == ValidatorConfig::MAX_VALIDATORS + 1
        );
    }

    #[test]
    fn new_rejects_duplicate_keys() {
        let mut keys = random_keys(3);
        keys[1] = keys[0].clone();
        let result = ValidatorConfig::new(keys, 3);
        assert_matches!(result, Err(ValidatorConfigError::DuplicateKey));
    }

    #[rstest::rstest]
    #[case::zero_quorum(0)]
    #[case::quorum_below_validator_count(2)]
    #[case::quorum_above_validator_count(4)]
    fn new_rejects_quorum_other_than_validator_count(#[case] quorum: u16) {
        let result = ValidatorConfig::new(random_keys(3), quorum);
        assert_matches!(
            result,
            Err(ValidatorConfigError::QuorumMustEqualValidatorCount { quorum: actual, count: 3 })
                if actual == quorum
        );
    }

    #[test]
    fn new_sorts_into_canonical_order() -> anyhow::Result<()> {
        let keys = random_keys(5);
        let forward = ValidatorConfig::new(keys.clone(), 5)?;

        let mut reversed = keys;
        reversed.reverse();
        let backward = ValidatorConfig::new(reversed, 5)?;

        // The canonical order makes the set and its commitment independent of input order.
        assert_eq!(forward.keys(), backward.keys());
        assert_eq!(forward.to_commitment(), backward.to_commitment());
        Ok(())
    }

    #[test]
    fn commitment_binds_the_quorum() -> anyhow::Result<()> {
        let config = ValidatorConfig::new(random_keys(3), 3)?;

        assert_eq!(config.to_elements()[0], Felt::from(config.quorum()));
        Ok(())
    }

    #[test]
    fn serde_round_trip() -> anyhow::Result<()> {
        let config = ValidatorConfig::new(random_keys(4), 4)?;
        let deserialized = ValidatorConfig::read_from_bytes(&config.to_bytes())?;
        assert_eq!(config, deserialized);

        Ok(())
    }
}
