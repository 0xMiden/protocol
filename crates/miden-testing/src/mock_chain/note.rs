use miden_processor::DeserializationError;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof, NoteMetadata};
use miden_protocol::transaction::InputNote;
use miden_tx::utils::{ByteReader, Deserializable, Serializable};
use winterfell::ByteWriter;

// MOCK CHAIN NOTE
// ================================================================================================

/// Represents a note that has been committed to the mock chain.
///
/// In a real chain, private notes would only expose their metadata and inclusion proof, but in
/// the mock chain we always retain the full [`Note`] details for convenient test access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockChainNote {
    note: Note,
    inclusion_proof: NoteInclusionProof,
}

impl MockChainNote {
    /// Creates a new [`MockChainNote`] from the full note and its inclusion proof.
    pub fn new(note: Note, inclusion_proof: NoteInclusionProof) -> Self {
        Self { note, inclusion_proof }
    }

    /// Returns the note's inclusion details.
    pub fn inclusion_proof(&self) -> &NoteInclusionProof {
        &self.inclusion_proof
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.note.metadata()
    }

    /// Returns the note's ID.
    pub fn id(&self) -> NoteId {
        self.note.id()
    }

    /// Returns the underlying note.
    pub fn note(&self) -> &Note {
        &self.note
    }
}

impl From<MockChainNote> for InputNote {
    fn from(value: MockChainNote) -> Self {
        InputNote::Authenticated {
            note: value.note,
            proof: value.inclusion_proof,
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for MockChainNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.note.write_into(target);
        self.inclusion_proof.write_into(target);
    }
}

impl Deserializable for MockChainNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note = Note::read_from(source)?;
        let inclusion_proof = NoteInclusionProof::read_from(source)?;
        Ok(MockChainNote { note, inclusion_proof })
    }
}
