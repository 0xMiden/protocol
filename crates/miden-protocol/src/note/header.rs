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
/// See [NoteDetailsCommitment] and [NoteMetadata] for additional details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteHeader {
    details_commitment: NoteDetailsCommitment,
    metadata: NoteMetadata,
}

impl NoteHeader {
    /// Returns a new [NoteHeader] instantiated from the specified note details commitment and
    /// metadata.
    pub fn new(details_commitment: NoteDetailsCommitment, metadata: NoteMetadata) -> Self {
        Self { details_commitment, metadata }
    }

    /// Returns the note's identifier.
    ///
    /// The [NoteId] commits to both the note details and the note metadata.
    pub fn id(&self) -> NoteId {
        NoteId::new(self.details_commitment(), self.metadata())
    }

    /// Returns the commitment to the note details, excluding metadata.
    pub fn details_commitment(&self) -> NoteDetailsCommitment {
        self.details_commitment
    }

    /// Returns a reference to the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        &self.metadata
    }

    /// Consumes self and returns the note header's metadata.
    pub fn into_metadata(self) -> NoteMetadata {
        self.metadata
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.details_commitment.write_into(target);
        self.metadata.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.details_commitment.get_size_hint() + self.metadata.get_size_hint()
    }
}

impl Deserializable for NoteHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let details_commitment = NoteDetailsCommitment::read_from(source)?;
        let metadata = NoteMetadata::read_from(source)?;

        Ok(Self::new(details_commitment, metadata))
    }
}
