use alloc::vec::Vec;

use miden_crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};

use crate::Word;
use crate::block::ValidatorKeys;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// BLOCK SIGNATURES ERROR
// ================================================================================================

/// Error returned when constructing [`BlockSignatures`] from validator key / signature pairs (see
/// [`BlockSignatures::new`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlockSignaturesError {
    #[error("supplied public key is not part of the validator set")]
    UnknownValidatorKey,
    #[error("multiple signatures were supplied for the same validator key")]
    DuplicateValidatorKey,
    #[error("validator keys at positions {positions:?} have no corresponding signature")]
    MissingSignatures { positions: Vec<usize> },
    #[error(transparent)]
    Verification(#[from] SignatureVerificationError),
}

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

// BLOCK SIGNATURES
// ================================================================================================

/// The positional set of validator signatures over a block header.
///
/// The signatures are positional with respect to a validator set (see [`ValidatorKeys`]): the
/// signature in slot `i` is produced by, and verified against, the validator key at index `i`.
/// Every validator in the set must sign; there is no partial-signing or threshold support (that
/// may be introduced as an n-of-m scheme in the future).
///
/// A value produced by [`BlockSignatures::new`] has one signature per validator key, each verified
/// against its key over the signed commitment, so it is always valid. Deserialized values carry no
/// such guarantee until checked with [`BlockSignatures::verify_against`], as block validation does
/// (see [`BlockHeader::validate_against_parent`](crate::block::BlockHeader)).
///
/// The only ways to construct a [`BlockSignatures`] are [`BlockSignatures::new`], which coalesces
/// and verifies validator key / signature pairs, and deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSignatures {
    /// Positional signatures; `signatures[i]` corresponds to validator key `i`.
    signatures: Vec<Signature>,
}

impl BlockSignatures {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Coalesces the supplied validator key / signature pairs into a [`BlockSignatures`] set
    /// positioned against `validator_keys`, and verifies each signature over `commitment`.
    ///
    /// Each signature is placed at the positional slot of its public key within `validator_keys`
    /// and verified against that key over `commitment`. Every validator key must have exactly one
    /// corresponding signature; the pairs may be given in any order.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a supplied public key is not part of `validator_keys`;
    /// - more than one signature is supplied for the same public key;
    /// - one or more validator keys have no corresponding signature;
    /// - a supplied signature does not verify against its validator key over `commitment`.
    pub fn new(
        commitment: Word,
        validator_keys: &ValidatorKeys,
        signatures: Vec<(PublicKey, Signature)>,
    ) -> Result<Self, BlockSignaturesError> {
        let mut slots: Vec<Option<Signature>> = alloc::vec![None; validator_keys.len()];
        for (public_key, signature) in signatures {
            let position = validator_keys
                .as_keys()
                .iter()
                .position(|key| *key == public_key)
                .ok_or(BlockSignaturesError::UnknownValidatorKey)?;
            if slots[position].is_some() {
                return Err(BlockSignaturesError::DuplicateValidatorKey);
            }
            slots[position] = Some(signature);
        }

        let missing_positions = slots
            .iter()
            .enumerate()
            .filter_map(|(position, slot)| slot.is_none().then_some(position))
            .collect::<Vec<_>>();
        if !missing_positions.is_empty() {
            return Err(BlockSignaturesError::MissingSignatures { positions: missing_positions });
        }
        let signatures = slots.into_iter().map(|slot| slot.expect("checked above")).collect();

        let block_signatures = Self { signatures };
        block_signatures.verify_against(commitment, validator_keys)?;
        Ok(block_signatures)
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

    /// Verifies the signatures positionally against `validator_keys` over `commitment`.
    ///
    /// This is the canonical verification of a positional signature set: the number of signatures
    /// must match the number of validator keys, and the signature in slot `i` must verify against
    /// the validator key at index `i`.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of signatures does not match the number of validator keys, or
    /// if a signature does not verify against the validator key at its position.
    pub fn verify_against(
        &self,
        commitment: Word,
        validator_keys: &ValidatorKeys,
    ) -> Result<(), SignatureVerificationError> {
        if self.signatures.len() != validator_keys.len() {
            return Err(SignatureVerificationError::SignatureCountMismatch {
                expected: validator_keys.len(),
                actual: self.signatures.len(),
            });
        }

        for (position, (signature, validator_key)) in
            self.signatures.iter().zip(validator_keys.as_keys()).enumerate()
        {
            if !signature.verify(commitment, validator_key) {
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
    use alloc::vec;
    use alloc::vec::Vec;

    use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey;

    use super::*;
    use crate::testing::random_secret_key::random_secret_key;

    /// Generates `count` validator signing keys alongside the [`ValidatorKeys`] set committing to
    /// their public keys.
    fn validator_set(count: usize) -> (Vec<SigningKey>, ValidatorKeys) {
        let signers: Vec<SigningKey> = (0..count).map(|_| random_secret_key()).collect();
        let keys = ValidatorKeys::new(signers.iter().map(|sk| sk.public_key()).collect()).unwrap();
        (signers, keys)
    }

    #[test]
    fn new_places_and_verifies_signatures_positionally() {
        let (signers, keys) = validator_set(5);
        let commitment = Word::empty();
        // All validators sign, supplied out of order.
        let pairs = signers.iter().rev().map(|sk| (sk.public_key(), sk.sign(commitment))).collect();

        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        assert_eq!(signatures.len(), 5);
        // Correct positional placement means the signatures verify against their keys.
        signatures.verify_against(commitment, &keys).unwrap();
    }

    #[test]
    fn new_supports_single_validator() {
        let (signers, keys) = validator_set(1);
        let commitment = Word::empty();
        let pairs = vec![(signers[0].public_key(), signers[0].sign(commitment))];

        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        assert_eq!(signatures.len(), 1);
        signatures.verify_against(commitment, &keys).unwrap();
    }

    #[test]
    fn new_rejects_unknown_key() {
        let (_, keys) = validator_set(3);
        let outsider = random_secret_key();
        let pairs = vec![(outsider.public_key(), outsider.sign(Word::empty()))];

        assert!(matches!(
            BlockSignatures::new(Word::empty(), &keys, pairs),
            Err(BlockSignaturesError::UnknownValidatorKey)
        ));
    }

    #[test]
    fn new_rejects_duplicate_key() {
        let (signers, keys) = validator_set(3);
        let commitment = Word::empty();
        let pairs = vec![
            (signers[0].public_key(), signers[0].sign(commitment)),
            (signers[0].public_key(), signers[0].sign(commitment)),
        ];

        assert!(matches!(
            BlockSignatures::new(commitment, &keys, pairs),
            Err(BlockSignaturesError::DuplicateValidatorKey)
        ));
    }

    #[test]
    fn new_rejects_missing_signatures() {
        let (signers, keys) = validator_set(4);
        let commitment = Word::empty();
        // Only one of four validators signs, so the other three are missing.
        let pairs = vec![(signers[0].public_key(), signers[0].sign(commitment))];

        match BlockSignatures::new(commitment, &keys, pairs) {
            Err(BlockSignaturesError::MissingSignatures { positions }) => {
                assert_eq!(positions.len(), 3);
            },
            other => panic!("expected MissingSignatures, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_invalid_signature() {
        let (signers, keys) = validator_set(3);
        let commitment = Word::empty();
        let outsider = random_secret_key();
        // A committed validator's key is paired with a signature that does not verify against it.
        let pairs = vec![
            (signers[0].public_key(), signers[0].sign(commitment)),
            (signers[1].public_key(), outsider.sign(commitment)),
            (signers[2].public_key(), signers[2].sign(commitment)),
        ];

        assert!(matches!(
            BlockSignatures::new(commitment, &keys, pairs),
            Err(BlockSignaturesError::Verification(
                SignatureVerificationError::InvalidSignatureAtPosition { .. }
            ))
        ));
    }

    #[test]
    fn verify_against_rejects_mismatched_keys() {
        let (signers, keys) = validator_set(3);
        let commitment = Word::empty();
        // A fully valid set signed by `keys`...
        let pairs = signers.iter().map(|sk| (sk.public_key(), sk.sign(commitment))).collect();
        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        // ...does not verify against a different validator set of the same size.
        let (_, other_keys) = validator_set(3);
        assert!(matches!(
            signatures.verify_against(commitment, &other_keys),
            Err(SignatureVerificationError::InvalidSignatureAtPosition { .. })
        ));
    }

    #[test]
    fn verify_against_rejects_count_mismatch() {
        let (signers, keys) = validator_set(3);
        let commitment = Word::empty();
        let pairs = signers.iter().map(|sk| (sk.public_key(), sk.sign(commitment))).collect();
        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        // A validator set of a different size cannot align positionally.
        let (_, other_keys) = validator_set(4);
        assert!(matches!(
            signatures.verify_against(commitment, &other_keys),
            Err(SignatureVerificationError::SignatureCountMismatch { expected: 4, actual: 3 })
        ));
    }

    #[test]
    fn serde_round_trip() {
        let (signers, keys) = validator_set(3);
        let commitment = Word::empty();
        let pairs = signers.iter().map(|sk| (sk.public_key(), sk.sign(commitment))).collect();
        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        let bytes = signatures.to_bytes();
        let deserialized = BlockSignatures::read_from_bytes(&bytes).unwrap();
        assert_eq!(signatures, deserialized);
    }
}
