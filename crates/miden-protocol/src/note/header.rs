use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteDetailsCommitment,
    NoteId,
    NoteMetadata,
    Serializable,
};

// NOTE HEADER
// ================================================================================================

/// Holds the strictly required, public information of a note.
///
/// See [NoteDetailsCommitment], [NoteId], and [NoteMetadata] for additional details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteHeader {
    note_details_commitment: NoteDetailsCommitment,
    note_metadata: NoteMetadata,
}

impl NoteHeader {
    /// Returns a new [NoteHeader] instantiated from the specified note details commitment and
    /// metadata.
    pub fn new(
        note_details_commitment: NoteDetailsCommitment,
        note_metadata: NoteMetadata,
    ) -> Self {
        Self { note_details_commitment, note_metadata }
    }

    /// Returns the note's identifier.
    ///
    /// The [NoteId] commits to both the note details and the note metadata.
    pub fn id(&self) -> NoteId {
        NoteId::new(self.commitment(), self.metadata())
    }

    /// Returns the commitment to the note details, excluding metadata.
    pub fn commitment(&self) -> NoteDetailsCommitment {
        self.note_details_commitment
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        &self.note_metadata
    }

    /// Consumes self and returns the note header's metadata.
    pub fn into_metadata(self) -> NoteMetadata {
        self.note_metadata
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.note_details_commitment.write_into(target);
        self.note_metadata.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.note_details_commitment.get_size_hint() + self.note_metadata.get_size_hint()
    }
}

impl Deserializable for NoteHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note_details_commitment = NoteDetailsCommitment::read_from(source)?;
        let note_metadata = NoteMetadata::read_from(source)?;

        Ok(Self { note_details_commitment, note_metadata })
    }
}
