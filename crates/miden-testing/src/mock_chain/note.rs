use miden_processor::serde::DeserializationError;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof, NoteMetadata};
use miden_protocol::transaction::InputNote;
use miden_tx::utils::serde::{ByteReader, ByteWriter, Deserializable, Serializable};

// MOCK CHAIN NOTE
// ================================================================================================

/// Represents a note that is stored in the mock chain.
///
/// Always holds the full [`Note`] object alongside its [`NoteInclusionProof`].
/// The note's privacy is determined by the note's own metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockChainNote {
    note: Note,
    inclusion_proof: NoteInclusionProof,
}

impl MockChainNote {
    /// Creates a new [`MockChainNote`] from a full note and its inclusion proof.
    pub fn new(note: Note, inclusion_proof: NoteInclusionProof) -> Self {
        Self { note, inclusion_proof }
    }

    /// Returns the note's inclusion proof.
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

    /// Returns a reference to the underlying note.
    pub fn note(&self) -> &Note {
        &self.note
    }
}

impl From<MockChainNote> for InputNote {
    fn from(value: MockChainNote) -> Self {
        InputNote::Authenticated { note: value.note, proof: value.inclusion_proof }
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
        Ok(Self { note, inclusion_proof })
    }
}
