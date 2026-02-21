use alloc::string::String;
use core::fmt::Display;

use miden_protocol_macros::WordWrapper;

use super::{Felt, Hasher, NoteDetails, Word};
use crate::WordError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// NOTE ID
// ================================================================================================

/// Returns a unique identifier of a note, which is simultaneously a commitment to the note.
///
/// Note ID is computed as:
///
/// > hash(recipient, asset_commitment),
///
/// where `recipient` is defined as:
///
/// > hash(hash(hash(serial_num, ZERO), script_root), storage_commitment)
///
/// This achieves the following properties:
/// - Every note can be reduced to a single unique ID.
/// - To compute a note ID, we do not need to know the note's serial_num. Knowing the hash of the
///   serial_num (as well as script root, input commitment, and note assets) is sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, WordWrapper)]
pub struct NoteId(Word);

impl NoteId {
    /// Returns a new [NoteId] instantiated from the provided note components.
    pub fn new(recipient: Word, asset_commitment: Word) -> Self {
        Self(Hasher::merge(&[recipient, asset_commitment]))
    }
}

impl Display for NoteId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// CONVERSIONS INTO NOTE ID
// ================================================================================================

impl From<&NoteDetails> for NoteId {
    fn from(note: &NoteDetails) -> Self {
        Self::new(note.recipient().digest(), note.assets().commitment())
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
