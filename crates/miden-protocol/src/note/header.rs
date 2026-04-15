use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteId,
    NoteMetadata,
    NoteMetadataHeader,
    Serializable,
    Word,
};
use crate::Hasher;

// NOTE HEADER
// ================================================================================================

/// Holds the strictly required, public information of a note.
///
/// See [NoteId] and [NoteMetadataHeader] for additional details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteHeader {
    note_id: NoteId,
    metadata_header: NoteMetadataHeader,
}

impl NoteHeader {
    /// Returns a new [NoteHeader] instantiated from the specified note ID and metadata header.
    pub fn new(note_id: NoteId, metadata_header: NoteMetadataHeader) -> Self {
        Self { note_id, metadata_header }
    }

    /// Returns the note's identifier.
    ///
    /// The [NoteId] value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        self.note_id
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.metadata_header.metadata()
    }

    /// Returns a reference to the note's metadata header.
    pub fn metadata_header(&self) -> &NoteMetadataHeader {
        &self.metadata_header
    }

    /// Consumes self and returns the note header's metadata.
    pub fn into_metadata(self) -> NoteMetadata {
        self.metadata_header.into_metadata()
    }

    /// Consumes self and returns the note header's metadata header.
    pub fn into_metadata_header(self) -> NoteMetadataHeader {
        self.metadata_header
    }

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
    ///
    /// This value is used primarily for authenticating notes consumed when they are consumed
    /// in a transaction.
    pub fn to_commitment(&self) -> Word {
        compute_note_commitment(self.id(), &self.metadata_header)
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
pub fn compute_note_commitment(id: NoteId, metadata_header: &NoteMetadataHeader) -> Word {
    Hasher::merge(&[id.as_word(), metadata_header.to_commitment()])
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.note_id.write_into(target);
        self.metadata_header.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.note_id.get_size_hint() + self.metadata_header.get_size_hint()
    }
}

impl Deserializable for NoteHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note_id = NoteId::read_from(source)?;
        let metadata_header = NoteMetadataHeader::read_from(source)?;

        Ok(Self::new(note_id, metadata_header))
    }
}
