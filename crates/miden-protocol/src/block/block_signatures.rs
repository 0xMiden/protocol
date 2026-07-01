use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

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

/// Error returned when verifying [`BlockSignatures`] against a validator set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlockSignaturesError {
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
/// signature in slot `i` is produced by, and verified against, the validator key at index `i`. A
/// slot is `None` when its validator did not sign.
///
/// This is a pure structural container of exactly [`BlockSignatures::SLOT_COUNT`] slots; it does
/// not enforce any quorum. The minimum number of valid signatures required to authorize a block is
/// a policy applied during validation (see [`BlockSignatures::MIN_SIGNATURES`] and
/// [`BlockHeader::validate_against_parent`](crate::block::BlockHeader)), not by this type. This
/// allows sub-quorum artifacts -- such as a single validator's signature or the genesis block's
/// signatures -- to be represented and serialized.
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
    /// This is a validation policy; it is enforced by
    /// [`BlockHeader::validate_against_parent`](crate::block::BlockHeader), not by this type's
    /// constructor or deserialization.
    pub const MIN_SIGNATURES: usize = 2;

    /// The number of signature slots, matching the size of a validator set.
    pub const SLOT_COUNT: usize = ValidatorKeys::COUNT;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BlockSignatures`] from the provided positional signature slots.
    pub fn new(signatures: [Option<Signature>; Self::SLOT_COUNT]) -> Self {
        Self { signatures }
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

    /// Verifies the filled signatures positionally against `validator_keys` over `commitment` and
    /// returns the number of valid signatures.
    ///
    /// This is the canonical verification of a positional signature set: the signature in slot `i`
    /// is verified against the validator key at index `i`. Empty slots are skipped, and a filled
    /// slot whose signature does not verify rejects the whole set.
    ///
    /// This does NOT enforce any quorum: it returns the count of valid signatures and lets the
    /// caller decide whether that meets the required threshold (see
    /// [`BlockSignatures::MIN_SIGNATURES`]).
    ///
    /// # Errors
    ///
    /// Returns an error if a filled signature does not verify against the validator key at its
    /// position.
    pub fn verify_against(
        &self,
        commitment: Word,
        validator_keys: &ValidatorKeys,
    ) -> Result<usize, BlockSignaturesError> {
        let mut valid_signatures = 0;
        for (position, (slot, validator_key)) in
            self.signatures.iter().zip(validator_keys.as_keys()).enumerate()
        {
            if let Some(signature) = slot {
                if !signature.verify(commitment, validator_key) {
                    return Err(BlockSignaturesError::InvalidSignatureAtPosition { position });
                }
                valid_signatures += 1;
            }
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
        Ok(Self::new(signatures))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
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

    /// Builds positional slots over `commitment` aligned to `keys`, signing the slots selected by
    /// `present`.
    fn signed_slots(
        keys: &ValidatorKeys,
        signers: &[SigningKey],
        commitment: Word,
        present: [bool; ValidatorKeys::COUNT],
    ) -> [Option<Signature>; ValidatorKeys::COUNT] {
        core::array::from_fn(|i| {
            if !present[i] {
                return None;
            }
            let key = &keys.as_keys()[i];
            let signer = signers.iter().find(|sk| &sk.public_key() == key).unwrap();
            Some(signer.sign(commitment))
        })
    }

    #[test]
    fn verify_against_counts_valid_signatures() {
        let (signers, keys) = validator_set();
        let commitment = Word::empty();
        let signatures = BlockSignatures::new(signed_slots(
            &keys,
            &signers,
            commitment,
            [true, false, true, false, false],
        ));

        assert_eq!(signatures.num_signatures(), 2);
        assert_eq!(signatures.verify_against(commitment, &keys).unwrap(), 2);
    }

    #[test]
    fn verify_against_rejects_invalid_signature() {
        let (signers, keys) = validator_set();
        let commitment = Word::empty();
        let mut slots =
            signed_slots(&keys, &signers, commitment, [true, true, false, false, false]);
        // Replace a committed validator's signature with one from a key not in the set.
        slots[1] = Some(random_secret_key().sign(commitment));
        let signatures = BlockSignatures::new(slots);

        let result = signatures.verify_against(commitment, &keys);
        assert!(matches!(
            result,
            Err(BlockSignaturesError::InvalidSignatureAtPosition { position: 1 })
        ));
    }

    #[test]
    fn serde_round_trip_allows_sub_quorum() {
        let (signers, keys) = validator_set();
        // A single filled slot is below the quorum but must still round-trip through the wire
        // format, as the type does not enforce a threshold.
        let signatures = BlockSignatures::new(signed_slots(
            &keys,
            &signers,
            Word::empty(),
            [true, false, false, false, false],
        ));
        assert_eq!(signatures.num_signatures(), 1);

        let bytes = signatures.to_bytes();
        let deserialized = BlockSignatures::read_from_bytes(&bytes).unwrap();
        assert_eq!(signatures, deserialized);
    }
}
