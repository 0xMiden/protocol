use super::{NoteDetailsCommitment, NoteId, NoteMetadata};

// NOTE HEADER
// ================================================================================================

/// Holds the strictly required, public information of a note.
///
/// See [NoteDetailsCommitment] and [NoteMetadata] for additional details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteHeader {
    metadata: NoteMetadata,
    details_commitment: NoteDetailsCommitment,
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

    /// Returns the commitment to the note's details, excluding metadata.
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
