use alloc::string::ToString;
use alloc::vec::Vec;

use crate::Word;
use crate::block::ValidatorConfig;
use crate::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
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
    #[error("block has {actual} signatures but the validator quorum is {quorum}")]
    QuorumNotMet { quorum: u16, actual: usize },
    #[error("block signature at position {position} does not verify against any validator key")]
    InvalidSignatureAtPosition { position: usize },
    #[error("block contains more than one signature of validator {public_key}")]
    DuplicateSigner { public_key: PublicKey },
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

/// The set of validator signatures over a block header.
///
/// A signature does not say which validator produced it. [`BlockSignatures::verify_against`]
/// finds the signer by checking the signature against the keys of a [`ValidatorConfig`], so the
/// set may cover any subset of the validators, in any order.
///
/// This is a plain, unchecked container: neither [`BlockSignatures::new`] nor deserialization
/// verify anything about the signatures they hold beyond their number. The only way to establish
/// that a [`BlockSignatures`] value authorizes a block is to call
/// [`BlockSignatures::verify_against`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSignatures {
    signatures: Vec<Signature>,
}

impl BlockSignatures {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BlockSignatures`] from the provided signatures.
    ///
    /// The signatures are not verified, see [`BlockSignatures::verify_against`].
    ///
    /// # Errors
    ///
    /// Returns an error if `signatures` contains more than [`ValidatorConfig::MAX_VALIDATORS`]
    /// signatures.
    pub fn new(signatures: Vec<Signature>) -> Result<Self, BlockSignaturesError> {
        if signatures.len() > ValidatorConfig::MAX_VALIDATORS {
            return Err(BlockSignaturesError::TooManySignatures { count: signatures.len() });
        }
        Ok(Self { signatures })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the signatures.
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

    /// Verifies that a quorum of `validator_config` signed `block_commitment`.
    ///
    /// The set is accepted if it holds at least [`ValidatorConfig::quorum`] signatures and every
    /// signature it holds is a valid signature of a distinct validator in `validator_config`.
    /// Signatures beyond the quorum are allowed.
    ///
    /// The signer of a signature is the validator whose key the signature verifies against. The
    /// recovery id of the signature is not used for this, because signers are not required to set
    /// it correctly.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the set holds fewer signatures than the quorum;
    /// - a signature does not verify against any key in `validator_config`;
    /// - two signatures were produced by the same validator.
    pub fn verify_against(
        &self,
        block_commitment: Word,
        validator_config: &ValidatorConfig,
    ) -> Result<(), SignatureVerificationError> {
        let quorum = validator_config.quorum();
        if self.signatures.len() < usize::from(quorum) {
            return Err(SignatureVerificationError::QuorumNotMet {
                quorum,
                actual: self.signatures.len(),
            });
        }

        // Every signature must belong to a distinct validator, so the number of signatures checked
        // against the quorum above is the number of validators that signed.
        let validator_keys = validator_config.keys();
        let mut has_signed = [false; ValidatorConfig::MAX_VALIDATORS];
        for (position, signature) in self.signatures.iter().enumerate() {
            let signer = validator_keys
                .iter()
                .position(|validator_key| signature.verify(block_commitment, validator_key))
                .ok_or(SignatureVerificationError::InvalidSignatureAtPosition { position })?;

            if core::mem::replace(&mut has_signed[signer], true) {
                return Err(SignatureVerificationError::DuplicateSigner {
                    public_key: validator_keys[signer].clone(),
                });
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
        Self::new(signatures).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use crate::testing::random_secret_key::random_secret_key;

    /// Returns `validator_count` random signers and the config committing to their keys with the
    /// given quorum.
    fn signers_with_quorum(
        validator_count: usize,
        quorum: u16,
    ) -> (Vec<SigningKey>, ValidatorConfig) {
        let (signers, config) = ValidatorConfig::random_with_signers(validator_count);
        let config = ValidatorConfig::new(config.keys().to_vec(), quorum).unwrap();
        (signers, config)
    }

    #[rstest::rstest]
    #[case::exactly_quorum(3, 2, 2)]
    #[case::above_quorum(3, 2, 3)]
    #[case::single_validator(1, 1, 1)]
    #[case::all_of_maximum(
        ValidatorConfig::MAX_VALIDATORS,
        ValidatorConfig::MAX_VALIDATORS as u16,
        ValidatorConfig::MAX_VALIDATORS
    )]
    fn verify_against_accepts_a_quorum(
        #[case] validator_count: usize,
        #[case] quorum: u16,
        #[case] signer_count: usize,
    ) {
        let (signers, config) = signers_with_quorum(validator_count, quorum);
        let commitment = Word::empty();

        let signatures = BlockSignatures::sign(&signers[..signer_count], commitment);

        assert_eq!(signatures.len(), signer_count);
        signatures.verify_against(commitment, &config).unwrap();
    }

    /// Signatures are matched to validator keys by verification, so neither their order nor the
    /// validators they skip matter.
    #[test]
    fn verify_against_accepts_signatures_in_any_order() {
        let (signers, config) = signers_with_quorum(3, 2);
        let commitment = Word::empty();

        let signatures =
            BlockSignatures::sign(&[signers[2].clone(), signers[0].clone()], commitment);

        signatures.verify_against(commitment, &config).unwrap();
    }

    /// Signers such as a KMS do not report the recovery id, so a signature must be accepted
    /// regardless of the recovery id it carries.
    #[test]
    fn verify_against_ignores_the_recovery_id() {
        let (signers, config) = signers_with_quorum(2, 2);
        let commitment = Word::empty();

        let signatures = signers
            .iter()
            .map(|signer| {
                let signature = signer.sign(commitment);
                Signature::from_sec1_bytes_and_recovery_id(
                    signature.to_sec1_bytes(),
                    signature.v() ^ 1,
                )
                .unwrap()
            })
            .collect();
        let signatures = BlockSignatures::new(signatures).unwrap();

        signatures.verify_against(commitment, &config).unwrap();
    }

    #[test]
    fn verify_against_rejects_fewer_signatures_than_quorum() {
        let (signers, config) = signers_with_quorum(3, 2);
        let commitment = Word::empty();

        let signatures = BlockSignatures::sign(&signers[..1], commitment);

        assert_matches!(
            signatures.verify_against(commitment, &config),
            Err(SignatureVerificationError::QuorumNotMet { quorum: 2, actual: 1 })
        );
    }

    #[test]
    fn verify_against_rejects_signer_outside_validator_set() {
        let (mut signers, config) = signers_with_quorum(3, 2);
        let commitment = Word::empty();

        // The validators alone meet the quorum; the valid signature of a key outside the set still
        // invalidates the block.
        signers.push(random_secret_key());
        let signatures = BlockSignatures::sign(&signers, commitment);

        assert_matches!(
            signatures.verify_against(commitment, &config),
            Err(SignatureVerificationError::InvalidSignatureAtPosition { position: 3 })
        );
    }

    #[test]
    fn verify_against_rejects_signatures_over_another_commitment() {
        let (signers, config) = signers_with_quorum(3, 2);

        let signatures = BlockSignatures::sign(&signers, Word::empty());

        assert_matches!(
            signatures.verify_against(Word::from([1u32, 2, 3, 4]), &config),
            Err(SignatureVerificationError::InvalidSignatureAtPosition { position: 0 })
        );
    }

    /// A validator must not be counted towards the quorum more than once.
    #[test]
    fn verify_against_rejects_duplicate_signer() {
        let (signers, config) = signers_with_quorum(3, 2);
        let commitment = Word::empty();

        let signatures =
            BlockSignatures::sign(&[signers[0].clone(), signers[0].clone()], commitment);

        assert_matches!(
            signatures.verify_against(commitment, &config),
            Err(SignatureVerificationError::DuplicateSigner { public_key })
                if public_key == signers[0].public_key()
        );
    }

    #[test]
    fn new_rejects_too_many_signatures() {
        let signer = random_secret_key();
        let signatures =
            alloc::vec![signer.sign(Word::empty()); ValidatorConfig::MAX_VALIDATORS + 1];

        assert_matches!(
            BlockSignatures::new(signatures.clone()),
            Err(BlockSignaturesError::TooManySignatures { count })
                if count == ValidatorConfig::MAX_VALIDATORS + 1
        );
        assert_matches!(
            BlockSignatures::read_from_bytes(&signatures.to_bytes()),
            Err(DeserializationError::InvalidValue(_))
        );
    }

    #[test]
    fn serde_round_trip() {
        let (signers, _) = ValidatorConfig::random_with_signers(3);
        let signatures = BlockSignatures::sign(&signers, Word::empty());

        let bytes = signatures.to_bytes();
        let deserialized = BlockSignatures::read_from_bytes(&bytes).unwrap();
        assert_eq!(signatures, deserialized);
    }
}
