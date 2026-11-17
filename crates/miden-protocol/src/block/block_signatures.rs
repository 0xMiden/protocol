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
    #[error("block is signed by key {public_key} which is not in the validator set")]
    SignerNotInValidatorSet { public_key: PublicKey },
    #[error("block signature of validator {public_key} is invalid")]
    InvalidSignature { public_key: PublicKey },
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
    #[error("block signature set contains more than one signature of validator {public_key}")]
    DuplicateSigner { public_key: PublicKey },
}

// VALIDATOR SIGNATURE
// ================================================================================================

/// A validator's signature over a block header, together with the public key of the validator that
/// produced it.
///
/// This is a plain container: it does not establish that the signature is valid for the key. See
/// [`BlockSignatures::verify_against`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSignature {
    public_key: PublicKey,
    signature: Signature,
}

impl ValidatorSignature {
    /// Returns a new [`ValidatorSignature`] from a validator's public key and its signature.
    pub fn new(public_key: PublicKey, signature: Signature) -> Self {
        Self { public_key, signature }
    }

    /// Returns the public key of the validator that produced the signature.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

// BLOCK SIGNATURES
// ================================================================================================

/// The set of validator signatures over a block header.
///
/// Each signature identifies the validator that produced it by public key (see
/// [`ValidatorSignature`]), so the set may cover any subset of a [`ValidatorConfig`]. The set
/// holds at most one signature per validator, kept in a canonical order (sorted by the serialized
/// public key).
///
/// Neither [`BlockSignatures::new`] nor deserialization verify the signatures they hold. The only
/// way to establish that a [`BlockSignatures`] value authorizes a block is to call
/// [`BlockSignatures::verify_against`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSignatures {
    /// Signatures of distinct validators, sorted by the validators' serialized public keys.
    signatures: Vec<ValidatorSignature>,
}

impl BlockSignatures {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BlockSignatures`] from the provided signatures.
    ///
    /// The signatures are sorted into a canonical order by the serialized public key of their
    /// validator. The signatures themselves are not verified, see
    /// [`BlockSignatures::verify_against`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `signatures` contains more than [`ValidatorConfig::MAX_VALIDATORS`] signatures;
    /// - `signatures` contains more than one signature of the same validator.
    pub fn new(mut signatures: Vec<ValidatorSignature>) -> Result<Self, BlockSignaturesError> {
        if signatures.len() > ValidatorConfig::MAX_VALIDATORS {
            return Err(BlockSignaturesError::TooManySignatures { count: signatures.len() });
        }

        signatures.sort_by_key(|signature| signature.public_key.to_bytes());

        // After sorting, signatures of the same validator are adjacent.
        if let Some(pair) =
            signatures.windows(2).find(|pair| pair[0].public_key == pair[1].public_key)
        {
            return Err(BlockSignaturesError::DuplicateSigner {
                public_key: pair[0].public_key.clone(),
            });
        }

        Ok(Self { signatures })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the signatures in canonical order.
    pub fn as_slice(&self) -> &[ValidatorSignature] {
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
    /// signature it holds is a valid signature of a validator in `validator_config`. Since the set
    /// holds at most one signature per validator, this means a quorum of distinct validators
    /// signed. Signatures beyond the quorum are allowed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the set holds fewer signatures than the quorum;
    /// - a signature is attributed to a key that is not in `validator_config`;
    /// - a signature does not verify against the key it is attributed to.
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

        for ValidatorSignature { public_key, signature } in &self.signatures {
            if !validator_config.keys().contains(public_key) {
                return Err(SignatureVerificationError::SignerNotInValidatorSet {
                    public_key: public_key.clone(),
                });
            }
            if !signature.verify(block_commitment, public_key) {
                return Err(SignatureVerificationError::InvalidSignature {
                    public_key: public_key.clone(),
                });
            }
        }

        Ok(())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for ValidatorSignature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.public_key.write_into(target);
        self.signature.write_into(target);
    }
}

impl Deserializable for ValidatorSignature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let public_key = PublicKey::read_from(source)?;
        let signature = Signature::read_from(source)?;
        Ok(Self { public_key, signature })
    }
}

impl Serializable for BlockSignatures {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.signatures.write_into(target);
    }
}

impl Deserializable for BlockSignatures {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let signatures = Vec::<ValidatorSignature>::read_from(source)?;
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
        let outsider = random_secret_key();

        // The validators alone meet the quorum; the valid signature of a key outside the set still
        // invalidates the block.
        signers.push(outsider.clone());
        let signatures = BlockSignatures::sign(&signers, commitment);

        assert_matches!(
            signatures.verify_against(commitment, &config),
            Err(SignatureVerificationError::SignerNotInValidatorSet { public_key })
                if public_key == outsider.public_key()
        );
    }

    #[test]
    fn verify_against_rejects_invalid_signature() {
        let (signers, config) = signers_with_quorum(3, 2);
        let commitment = Word::empty();
        let outsider = random_secret_key();

        // The first two validators meet the quorum; the third is attributed a signature produced
        // by another key.
        let forged = ValidatorSignature::new(signers[2].public_key(), outsider.sign(commitment));
        let mut signatures = BlockSignatures::sign(&signers[..2], commitment).as_slice().to_vec();
        signatures.push(forged);
        let signatures = BlockSignatures::new(signatures).unwrap();

        assert_matches!(
            signatures.verify_against(commitment, &config),
            Err(SignatureVerificationError::InvalidSignature { public_key })
                if public_key == signers[2].public_key()
        );
    }

    #[test]
    fn verify_against_rejects_signatures_over_another_commitment() {
        let (signers, config) = signers_with_quorum(3, 2);

        let signatures = BlockSignatures::sign(&signers, Word::empty());

        assert_matches!(
            signatures.verify_against(Word::from([1u32, 2, 3, 4]), &config),
            Err(SignatureVerificationError::InvalidSignature { .. })
        );
    }

    /// A validator must not be counted towards the quorum more than once.
    #[test]
    fn new_rejects_duplicate_signer() {
        let signer = random_secret_key();
        let signature = ValidatorSignature::new(signer.public_key(), signer.sign(Word::empty()));

        let result = BlockSignatures::new(alloc::vec![signature.clone(), signature]);

        assert_matches!(
            result,
            Err(BlockSignaturesError::DuplicateSigner { public_key })
                if public_key == signer.public_key()
        );
    }

    #[test]
    fn deserialization_rejects_duplicate_signer() {
        let signer = random_secret_key();
        let signature = ValidatorSignature::new(signer.public_key(), signer.sign(Word::empty()));
        let bytes = alloc::vec![signature.clone(), signature].to_bytes();

        assert_matches!(
            BlockSignatures::read_from_bytes(&bytes),
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
