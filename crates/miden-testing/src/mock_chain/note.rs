use miden_processor::serde::DeserializationError;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof, NoteMetadata};
use miden_protocol::transaction::{InputNote, OutputNote};
use miden_tx::utils::serde::{ByteReader, ByteWriter, Deserializable, Serializable};

// MOCK CHAIN NOTE
// ================================================================================================

/// Represents a note stored in the mock chain.
///
/// Mirrors real chain behavior: public notes carry full details while private notes carry only
/// a [`NoteHeader`] (id + metadata). Full details for private notes are expected to be held
/// locally, off-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockChainNote {
    note: OutputNote,
    proof: NoteInclusionProof,
}

impl MockChainNote {
    pub fn new(note: OutputNote, proof: NoteInclusionProof) -> Self {
        Self { note, proof }
    }

    /// Returns the note's inclusion proof.
    pub fn inclusion_proof(&self) -> &NoteInclusionProof {
        &self.proof
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.note.metadata()
    }

    /// Returns the note's ID.
    pub fn id(&self) -> NoteId {
        self.note.id()
    }

    /// Returns the underlying note if it is public.
    pub fn note(&self) -> Option<&Note> {
        match &self.note {
            OutputNote::Public(note) => Some(note.as_note()),
            OutputNote::Private(_) => None,
        }
    }
}

impl TryFrom<MockChainNote> for InputNote {
    type Error = anyhow::Error;

    fn try_from(value: MockChainNote) -> Result<Self, Self::Error> {
        match value.note {
            OutputNote::Public(note) => Ok(InputNote::Authenticated {
                note: note.into_note(),
                proof: value.proof,
            }),
            OutputNote::Private(_) => Err(anyhow::anyhow!(
                "private notes in the mock chain cannot be converted into input notes due to missing details"
            )),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for MockChainNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.note.write_into(target);
        self.proof.write_into(target);
    }
}

impl Deserializable for MockChainNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note = OutputNote::read_from(source)?;
        let proof = NoteInclusionProof::read_from(source)?;
        Ok(Self { note, proof })
    }
}
