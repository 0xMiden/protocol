use alloc::string::String;
use core::fmt::Display;

use miden_crypto_derive::WordWrapper;

use super::{Felt, NoteDetailsCommitment, NoteMetadata};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Hasher, Word, WordError};

// NOTE ID
// ================================================================================================

/// A unique identifier of a note.
///
/// The note ID is computed as:
///
/// > hash(NOTE_DETAILS_COMMITMENT || NOTE_METADATA_COMMITMENT)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct NoteId(Word);

impl NoteId {
    /// Returns a new [`NoteId`] from the provided details commitment and metadata.
    pub fn new(details_commitment: NoteDetailsCommitment, metadata: &NoteMetadata) -> Self {
        Self(Hasher::merge(&[details_commitment.as_word(), metadata.to_commitment()]))
    }
}

impl Display for NoteId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl NoteId {
    /// Attempts to convert from a hexadecimal string to [NoteId].
    ///
    /// Callers must ensure the provided value is an actual [`NoteId`].
    pub fn try_from_hex(hex_value: &str) -> Result<NoteId, WordError> {
        Word::try_from(hex_value).map(NoteId::from_raw)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0.to_bytes());
    }

    fn get_size_hint(&self) -> usize {
        Word::SERIALIZED_SIZE
    }
}

impl Deserializable for NoteId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id = Word::read_from(source)?;
        Ok(Self(id))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::NoteId;

    #[test]
    fn note_id_try_from_hex() {
        let note_id_hex = "0xc9d31c82c098e060c9b6e3af2710b3fc5009a1a6f82ef9465f8f35d1f5ba4a80";
        let note_id = NoteId::try_from_hex(note_id_hex).unwrap();

        assert_eq!(note_id.as_word().to_string(), note_id_hex)
    }
}
