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
    #[error(transparent)]
    Verification(#[from] SignatureVerificationError),
}

/// Error returned when verifying [`BlockSignatures`] against a validator set (see
/// [`BlockSignatures::verify_against`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureVerificationError {
    #[error(
        "block signature at position {position} does not verify against the validator key at that position"
    )]
    InvalidSignatureAtPosition { position: usize },
    #[error(
        "{valid} valid signatures were provided but at least {min} are required",
        min = BlockSignatures::MIN_SIGNATURES,
    )]
    InsufficientSignatures { valid: usize },
}

// BLOCK SIGNATURES
// ================================================================================================

/// The positional set of validator signatures over a block header.
///
/// The signatures are positional with respect to a validator set (see [`ValidatorKeys`]): the
/// signature in slot `i` is produced by, and verified against, the validator key at index `i`. A
/// slot is `None` when its validator did not sign.
///
/// It has exactly [`BlockSignatures::SLOT_COUNT`] slots. A value produced by
/// [`BlockSignatures::new`] has its present signatures verified against a validator set and carries
/// at least [`BlockSignatures::MIN_SIGNATURES`] valid signatures, so it is always valid.
/// Deserialized values carry no such guarantee until checked with
/// [`BlockSignatures::verify_against`], as block validation does (see
/// [`BlockHeader::validate_against_parent`](crate::block::BlockHeader)).
///
/// The only ways to construct a [`BlockSignatures`] are [`BlockSignatures::new`], which coalesces
/// and verifies validator key / signature pairs, and deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSignatures {
    /// Positional signature slots; `signatures[i]` corresponds to validator key `i`.
    signatures: [Option<Signature>; ValidatorKeys::COUNT],
}

impl BlockSignatures {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The minimum number of valid signatures required to authorize a block.
    ///
    /// This minimum is enforced by [`BlockSignatures::verify_against`] -- and therefore by
    /// [`BlockSignatures::new`] and [`BlockHeader::validate_against_parent`](crate::block::BlockHeader),
    /// which both call it -- but not by deserialization.
    pub const MIN_SIGNATURES: usize = 2;

    /// The number of signature slots, matching the size of a validator set.
    pub const SLOT_COUNT: usize = ValidatorKeys::COUNT;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Coalesces the supplied validator key / signature pairs into a [`BlockSignatures`] set
    /// positioned against `validator_keys`, and verifies each signature over `commitment`.
    ///
    /// Each signature is placed at the positional slot of its public key within `validator_keys`
    /// and verified against that key over `commitment`; slots for validators without a supplied
    /// signature are left empty. The pairs may be given in any order.
    ///
    /// The returned set is therefore always cryptographically valid and meets the minimum of
    /// [`BlockSignatures::MIN_SIGNATURES`] valid signatures.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a supplied public key is not part of `validator_keys`;
    /// - more than one signature is supplied for the same public key;
    /// - a supplied signature does not verify against its validator key over `commitment`;
    /// - fewer than [`BlockSignatures::MIN_SIGNATURES`] valid signatures are supplied.
    pub fn new(
        commitment: Word,
        validator_keys: &ValidatorKeys,
        signatures: Vec<(PublicKey, Signature)>,
    ) -> Result<Self, BlockSignaturesError> {
        let mut slots: [Option<Signature>; Self::SLOT_COUNT] = core::array::from_fn(|_| None);
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

        let block_signatures = Self { signatures: slots };
        block_signatures.verify_against(commitment, validator_keys)?;
        Ok(block_signatures)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the positional signature slots, where slot `i` corresponds to validator key `i`.
    pub fn as_slots(&self) -> &[Option<Signature>] {
        &self.signatures
    }

    /// Returns the number of signature slots, which is always [`BlockSignatures::SLOT_COUNT`].
    pub fn len(&self) -> usize {
        Self::SLOT_COUNT
    }

    /// Returns `false`, as there is always one signature slot per validator key.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns the number of filled signature slots.
    pub fn num_signatures(&self) -> usize {
        self.signatures.iter().filter(|slot| slot.is_some()).count()
    }

    // VERIFICATION
    // --------------------------------------------------------------------------------------------

    /// Verifies the filled signatures positionally against `validator_keys` over `commitment`,
    /// requiring at least [`BlockSignatures::MIN_SIGNATURES`] valid signatures, and returns the
    /// number of valid signatures.
    ///
    /// This is the canonical verification of a positional signature set: the signature in slot `i`
    /// is verified against the validator key at index `i`. Empty slots are skipped, and a filled
    /// slot whose signature does not verify rejects the whole set.
    ///
    /// # Errors
    ///
    /// Returns an error if a filled signature does not verify against the validator key at its
    /// position, or if fewer than [`BlockSignatures::MIN_SIGNATURES`] valid signatures are present.
    pub fn verify_against(
        &self,
        commitment: Word,
        validator_keys: &ValidatorKeys,
    ) -> Result<usize, SignatureVerificationError> {
        let mut valid_signatures = 0;
        for (position, (slot, validator_key)) in
            self.signatures.iter().zip(validator_keys.as_keys()).enumerate()
        {
            if let Some(signature) = slot {
                if !signature.verify(commitment, validator_key) {
                    return Err(SignatureVerificationError::InvalidSignatureAtPosition {
                        position,
                    });
                }
                valid_signatures += 1;
            }
        }

        if valid_signatures < Self::MIN_SIGNATURES {
            return Err(SignatureVerificationError::InsufficientSignatures {
                valid: valid_signatures,
            });
        }
        Ok(valid_signatures)
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
        let signatures = <[Option<Signature>; Self::SLOT_COUNT]>::read_from(source)?;
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

    /// Generates a full set of validator signing keys alongside the [`ValidatorKeys`] set
    /// committing to their public keys.
    fn validator_set() -> (Vec<SigningKey>, ValidatorKeys) {
        let signers: Vec<SigningKey> =
            (0..ValidatorKeys::COUNT).map(|_| random_secret_key()).collect();
        let keys = ValidatorKeys::new(core::array::from_fn(|i| signers[i].public_key())).unwrap();
        (signers, keys)
    }

    #[test]
    fn new_places_and_verifies_signatures_positionally() {
        let (signers, keys) = validator_set();
        let commitment = Word::empty();
        // Two arbitrary validators sign, supplied out of order.
        let pairs = vec![
            (signers[3].public_key(), signers[3].sign(commitment)),
            (signers[0].public_key(), signers[0].sign(commitment)),
        ];

        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        assert_eq!(signatures.num_signatures(), 2);
        // Correct positional placement means the signatures verify against their keys.
        assert_eq!(signatures.verify_against(commitment, &keys).unwrap(), 2);
    }

    #[test]
    fn new_rejects_unknown_key() {
        let (_, keys) = validator_set();
        let outsider = random_secret_key();
        let pairs = vec![(outsider.public_key(), outsider.sign(Word::empty()))];

        assert!(matches!(
            BlockSignatures::new(Word::empty(), &keys, pairs),
            Err(BlockSignaturesError::UnknownValidatorKey)
        ));
    }

    #[test]
    fn new_rejects_duplicate_key() {
        let (signers, keys) = validator_set();
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
    fn new_rejects_invalid_signature() {
        let (signers, keys) = validator_set();
        let commitment = Word::empty();
        let outsider = random_secret_key();
        // A committed validator's key is paired with a signature that does not verify against it.
        let pairs = vec![
            (signers[0].public_key(), signers[0].sign(commitment)),
            (signers[1].public_key(), outsider.sign(commitment)),
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
        let (signers, keys) = validator_set();
        let commitment = Word::empty();
        // A fully valid set signed by `keys`...
        let pairs = keys
            .as_keys()
            .iter()
            .map(|key| {
                let signer = signers.iter().find(|sk| &sk.public_key() == key).unwrap();
                (key.clone(), signer.sign(commitment))
            })
            .collect();
        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        // ...does not verify against a different validator set.
        let (_, other_keys) = validator_set();
        assert!(matches!(
            signatures.verify_against(commitment, &other_keys),
            Err(SignatureVerificationError::InvalidSignatureAtPosition { .. })
        ));
    }

    #[test]
    fn new_rejects_insufficient_signatures() {
        let (signers, keys) = validator_set();
        let commitment = Word::empty();
        // A single valid signature is below the minimum.
        let pairs = vec![(signers[0].public_key(), signers[0].sign(commitment))];

        assert!(matches!(
            BlockSignatures::new(commitment, &keys, pairs),
            Err(BlockSignaturesError::Verification(
                SignatureVerificationError::InsufficientSignatures { valid: 1 }
            ))
        ));
    }

    #[test]
    fn serde_round_trip() {
        let (signers, keys) = validator_set();
        let commitment = Word::empty();
        let pairs = vec![
            (signers[0].public_key(), signers[0].sign(commitment)),
            (signers[1].public_key(), signers[1].sign(commitment)),
        ];
        let signatures = BlockSignatures::new(commitment, &keys, pairs).unwrap();

        let bytes = signatures.to_bytes();
        let deserialized = BlockSignatures::read_from_bytes(&bytes).unwrap();
        assert_eq!(signatures, deserialized);
    }
}
