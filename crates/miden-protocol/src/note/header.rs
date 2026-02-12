use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteId,
    NoteMetadata,
    Serializable,
    Word,
};
use crate::Hasher;

// NOTE HEADER
// ================================================================================================

/// Holds the strictly required, public information of a note.
///
/// See [NoteId] and [NoteMetadata] for additional details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteHeader {
    note_id: NoteId,
    note_metadata: NoteMetadata,
}

impl NoteHeader {
    /// Returns a new [NoteHeader] instantiated from the specified note ID and metadata.
    pub fn new(note_id: NoteId, note_metadata: NoteMetadata) -> Self {
        Self { note_id, note_metadata }
    }

    /// Returns the note's identifier.
    ///
    /// The [NoteId] value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        self.note_id
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        &self.note_metadata
    }

    /// Consumes self and returns the note header's metadata.
    pub fn into_metadata(self) -> NoteMetadata {
        self.note_metadata
    }

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
    ///
    /// This value is used primarily for authenticating notes consumed when they are consumed
    /// in a transaction.
    pub fn commitment(&self) -> Word {
        compute_note_commitment(self.id(), self.metadata())
    }
}

// UTILITIES
// ================================================================================================

/// Returns a commitment to the note and its metadata.
///
/// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
///
/// This value is used primarily for authenticating notes consumed when they are consumed
/// in a transaction.
pub fn compute_note_commitment(id: NoteId, metadata: &NoteMetadata) -> Word {
    Hasher::merge(&[id.as_word(), metadata.to_commitment()])
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.note_id.write_into(target);
        self.note_metadata.write_into(target);
    }
}

impl Deserializable for NoteHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note_id = NoteId::read_from(source)?;
        let note_metadata = NoteMetadata::read_from(source)?;

        Ok(Self { note_id, note_metadata })
    }
}
