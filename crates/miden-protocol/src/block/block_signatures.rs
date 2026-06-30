use alloc::string::ToString;

use miden_crypto::dsa::ecdsa_k256_keccak::Signature;

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

/// Error returned when constructing an invalid [`BlockSignatures`] set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlockSignaturesError {
    #[error(
        "block has {present} signature slots filled but requires at least {min}",
        min = BlockSignatures::MIN_SIGNATURES,
    )]
    TooFewSignatures { present: usize },
}

// BLOCK SIGNATURES
// ================================================================================================

/// The positional set of validator signatures over a block header.
///
/// The signatures are positional with respect to the validator set committed to by the block's
/// parent (see [`ValidatorKeys`]): the signature in slot `i` is produced by, and verified against,
/// the validator key at index `i`. A slot is `None` when its validator did not sign.
///
/// There is exactly one slot per validator key ([`BlockSignatures::SLOT_COUNT`] in total), of which
/// at least [`BlockSignatures::MIN_SIGNATURES`] must be filled. Whether the filled signatures
/// actually verify against the parent's validator keys is checked during block validation, not
/// here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSignatures {
    /// Positional signature slots; `signatures[i]` corresponds to validator key `i`.
    signatures: [Option<Signature>; ValidatorKeys::COUNT],
}

impl BlockSignatures {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The minimum number of filled signature slots required for a valid block.
    pub const MIN_SIGNATURES: usize = 2;

    /// The number of signature slots, matching the size of a validator set.
    pub const SLOT_COUNT: usize = ValidatorKeys::COUNT;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`BlockSignatures`] from the provided positional signature slots.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than [`BlockSignatures::MIN_SIGNATURES`] slots are filled.
    pub fn new(
        signatures: [Option<Signature>; Self::SLOT_COUNT],
    ) -> Result<Self, BlockSignaturesError> {
        let present = signatures.iter().filter(|slot| slot.is_some()).count();
        if present < Self::MIN_SIGNATURES {
            return Err(BlockSignaturesError::TooFewSignatures { present });
        }

        Ok(Self { signatures })
    }

    /// Returns a new [`BlockSignatures`] from the provided positional signature slots without
    /// validation.
    ///
    /// # Warning
    ///
    /// This constructor does not validate that enough slots are filled, which could cause errors
    /// downstream.
    pub fn new_unchecked(signatures: [Option<Signature>; Self::SLOT_COUNT]) -> Self {
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
        Self::new(signatures).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Word;
    use crate::testing::random_secret_key::random_secret_key;

    fn signature() -> Signature {
        random_secret_key().sign(Word::empty())
    }

    /// Builds [`BlockSignatures::SLOT_COUNT`] slots with the first `filled` slots signed and the
    /// rest empty.
    fn slots(filled: usize) -> [Option<Signature>; BlockSignatures::SLOT_COUNT] {
        core::array::from_fn(|i| if i < filled { Some(signature()) } else { None })
    }

    #[test]
    fn new_accepts_minimum_filled_slots() {
        let signatures = BlockSignatures::new(slots(BlockSignatures::MIN_SIGNATURES)).unwrap();
        assert_eq!(signatures.len(), BlockSignatures::SLOT_COUNT);
        assert_eq!(signatures.num_signatures(), BlockSignatures::MIN_SIGNATURES);
    }

    #[test]
    fn new_accepts_full_slots() {
        let signatures = BlockSignatures::new(slots(BlockSignatures::SLOT_COUNT)).unwrap();
        assert_eq!(signatures.num_signatures(), BlockSignatures::SLOT_COUNT);
    }

    #[test]
    fn new_rejects_too_few_signatures() {
        let result = BlockSignatures::new(slots(BlockSignatures::MIN_SIGNATURES - 1));
        assert!(matches!(result, Err(BlockSignaturesError::TooFewSignatures { .. })));
    }

    #[test]
    fn serde_round_trip() {
        let signatures = BlockSignatures::new(slots(BlockSignatures::MIN_SIGNATURES)).unwrap();
        let bytes = signatures.to_bytes();
        let deserialized = BlockSignatures::read_from_bytes(&bytes).unwrap();
        assert_eq!(signatures, deserialized);
    }
}
