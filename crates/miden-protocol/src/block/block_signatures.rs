use alloc::vec::Vec;

use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

use crate::Word;
use crate::block::ValidatorConfig;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// SIGNATURE VERIFICATION ERROR
// ================================================================================================

/// Error returned when verifying [`BlockSignatures`] against a validator set (see
/// [`BlockSignatures::verify_against`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureVerificationError {
    #[error("block has {actual} signatures but the validator set has {expected} keys")]
    SignatureCountMismatch { expected: usize, actual: usize },
    #[error(
        "block signature at position {position} does not verify against the validator key at that position"
    )]
    InvalidSignatureAtPosition { position: usize },
}

// BLOCK SIGNATURES ERROR
// ================================================================================================

/// Error returned when constructing an invalid [`BlockSignatures`] set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlockSignaturesError {
    #[error(
        "block signature set contains {count} signatures but must contain at most {max}",
        max = ValidatorConfig::MAX_VALIDATORS,
    )]
    TooManySignatures { count: usize },
}

// BLOCK SIGNATURES
// ================================================================================================

/// The set of validator signatures over a block header ordered by validator key.
///
/// The signatures are expected to be ordered with respect to a validator set (see
/// [`ValidatorConfig`]): the signature in slot `i` is produced by, and verified against, the
/// validator key at index `i`. Every validator in the set must sign; there is no partial-signing
/// support.
///
/// TODO(validator_quorum): [`ValidatorConfig::quorum`] is committed to by the block header but not
/// enforced here yet. Enforcing it requires signatures that identify the validator they belong to,
/// so that a partial set can still be matched against the validator keys.
///
/// This is a plain, unchecked container: neither [`BlockSignatures::new`] nor deserialization
/// verify anything about the signatures they hold. The only way to establish that a
/// [`BlockSignatures`] value is valid is to call [`BlockSignatures::verify_against`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSignatures {
    /// Positional signatures; `signatures[i]` corresponds to validator key `i`.
    signatures: Vec<Signature>,
}

impl BlockSignatures {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BlockSignatures`] from the provided signatures, ordered positionally.
    ///
    /// This performs no validation beyond checking that the number of signatures does not exceed
    /// [`ValidatorConfig::MAX_VALIDATORS`]: the caller is responsible for ordering `signatures` to align
    /// with the validator set it is meant to be checked against. Call
    /// [`BlockSignatures::verify_against`] to establish that the signatures are valid.
    pub fn new(signatures: Vec<Signature>) -> Result<Self, BlockSignaturesError> {
        if signatures.len() > ValidatorConfig::MAX_VALIDATORS {
            return Err(BlockSignaturesError::TooManySignatures { count: signatures.len() });
        }
        Ok(Self { signatures })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the positional signatures, where signature `i` corresponds to validator key `i`.
    pub fn as_signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Returns the number of signatures.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Returns `true` if there are no signatures.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    // VERIFICATION
    // --------------------------------------------------------------------------------------------

    /// Verifies the signatures positionally against `validator_config` over `block_commitment`.
    ///
    /// This is the canonical verification of an ordered signature set, and the only place that
    /// establishes a [`BlockSignatures`] value is valid: the number of signatures must match the
    /// number of validator keys, and the signature in slot `i` must verify against the validator
    /// key at index `i`.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of signatures does not match the number of validator keys, or
    /// if a signature does not verify against the validator key at its position.
    pub fn verify_against(
        &self,
        block_commitment: Word,
        validator_config: &ValidatorConfig,
    ) -> Result<(), SignatureVerificationError> {
        if self.signatures.len() != validator_config.len() {
            return Err(SignatureVerificationError::SignatureCountMismatch {
                expected: validator_config.len(),
                actual: self.signatures.len(),
            });
        }

        for (position, (signature, validator_key)) in
            self.signatures.iter().zip(validator_config.as_keys()).enumerate()
        {
            if !signature.verify(block_commitment, validator_key) {
                return Err(SignatureVerificationError::InvalidSignatureAtPosition { position });
            }
        }

        Ok(())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BlockSignatures {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.signatures.write_into(target);
    }
}

impl Deserializable for BlockSignatures {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let signatures = Vec::<Signature>::read_from(source)?;
        Ok(Self { signatures })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::random_secret_key::random_secret_key;
    use crate::testing::validator_config::{random_validator_set, sign_all};

    #[test]
    fn verify_against_accepts_correctly_ordered_signatures() {
        let (signers, keys) = random_validator_set(5);
        let commitment = Word::empty();

        let signatures = sign_all(&keys, &signers, commitment);

        assert_eq!(signatures.len(), 5);
        signatures.verify_against(commitment, &keys).unwrap();
    }

    #[test]
    fn verify_against_rejects_invalid_signature() {
        let (signers, keys) = random_validator_set(3);
        let commitment = Word::empty();
        let outsider = random_secret_key();

        // Position 1 holds a signature that does not verify against the key committed there.
        let mut signatures = sign_all(&keys, &signers, commitment).as_signatures().to_vec();
        signatures[1] = outsider.sign(commitment);
        let signatures = BlockSignatures::new(signatures).unwrap();

        assert!(matches!(
            signatures.verify_against(commitment, &keys),
            Err(SignatureVerificationError::InvalidSignatureAtPosition { position: 1 })
        ));
    }

    #[test]
    fn verify_against_rejects_mismatched_keys() {
        let (signers, keys) = random_validator_set(3);
        let commitment = Word::empty();
        let signatures = sign_all(&keys, &signers, commitment);

        // The same, fully valid set does not verify against a different validator set of the same
        // size.
        let (_, other_keys) = random_validator_set(3);
        assert!(matches!(
            signatures.verify_against(commitment, &other_keys),
            Err(SignatureVerificationError::InvalidSignatureAtPosition { .. })
        ));
    }

    #[test]
    fn verify_against_rejects_count_mismatch() {
        let (signers, keys) = random_validator_set(3);
        let commitment = Word::empty();
        let signatures = sign_all(&keys, &signers, commitment);

        // A validator set of a different size cannot align positionally.
        let (_, other_keys) = random_validator_set(4);
        assert!(matches!(
            signatures.verify_against(commitment, &other_keys),
            Err(SignatureVerificationError::SignatureCountMismatch { expected: 4, actual: 3 })
        ));
    }

    #[test]
    fn serde_round_trip() {
        let (signers, keys) = random_validator_set(3);
        let commitment = Word::empty();
        let signatures = sign_all(&keys, &signers, commitment);

        let bytes = signatures.to_bytes();
        let deserialized = BlockSignatures::read_from_bytes(&bytes).unwrap();
        assert_eq!(signatures, deserialized);
    }
}
