use alloc::string::String;
use core::fmt::Display;

use miden_crypto_derive::WordWrapper;

use super::{Felt, Hasher, NoteDetails, Word};
use crate::WordError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// NOTE DETAILS COMMITMENT
// ================================================================================================

/// A commitment to a note's details, without note metadata.
///
/// This value commits to the note's recipient and assets. Together with the note metadata
/// commitment it is used to derive the note's [`super::NoteId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct NoteDetailsCommitment(Word);

impl NoteDetailsCommitment {
    /// Returns a new [`NoteDetailsCommitment`] instantiated from the provided note components.
    pub fn new(recipient: Word, asset_commitment: Word) -> Self {
        Self(Hasher::merge(&[recipient, asset_commitment]))
    }
}

impl Display for NoteDetailsCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// CONVERSIONS INTO NOTE DETAILS COMMITMENT
// ================================================================================================

impl From<&NoteDetails> for NoteDetailsCommitment {
    fn from(note: &NoteDetails) -> Self {
        Self::new(note.recipient().digest(), note.assets().commitment())
    }
}

impl NoteDetailsCommitment {
    /// Attempts to convert from a hexadecimal string to [`NoteDetailsCommitment`].
    ///
    /// Callers must ensure the provided value is an actual [`NoteDetailsCommitment`].
    pub fn try_from_hex(hex_value: &str) -> Result<Self, WordError> {
        Word::try_from(hex_value).map(Self::from_raw)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteDetailsCommitment {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0.to_bytes());
    }

    fn get_size_hint(&self) -> usize {
        Word::SERIALIZED_SIZE
    }
}

impl Deserializable for NoteDetailsCommitment {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let commitment = Word::read_from(source)?;
        Ok(Self(commitment))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::NoteDetailsCommitment;

    #[test]
    fn note_details_commitment_try_from_hex() {
        let commitment_hex = "0xc9d31c82c098e060c9b6e3af2710b3fc5009a1a6f82ef9465f8f35d1f5ba4a80";
        let commitment = NoteDetailsCommitment::try_from_hex(commitment_hex).unwrap();

        assert_eq!(commitment.as_word().to_string(), commitment_hex)
    }
}
