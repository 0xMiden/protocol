use miden_processor::DeserializationError;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof, NoteMetadata};
use miden_protocol::transaction::InputNote;
use miden_tx::utils::{ByteReader, Deserializable, Serializable};
use winterfell::ByteWriter;

// MOCK CHAIN NOTE
// ================================================================================================

/// Represents a note that is stored in the mock chain.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockChainNote {
    /// Details for a private note only include its [`NoteMetadata`] and [`NoteInclusionProof`].
    /// Other details needed to consume the note are expected to be stored locally, off-chain.
    Private(NoteId, NoteMetadata, NoteInclusionProof),
    /// Contains the full [`Note`] object alongside its [`NoteInclusionProof`].
    Public(Note, NoteInclusionProof),
}

impl MockChainNote {
    /// Returns the note's inclusion details.
    pub fn inclusion_proof(&self) -> &NoteInclusionProof {
        match self {
            MockChainNote::Private(_, _, inclusion_proof)
            | MockChainNote::Public(_, inclusion_proof) => inclusion_proof,
        }
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        match self {
            MockChainNote::Private(_, metadata, _) => metadata,
            MockChainNote::Public(note, _) => note.metadata(),
        }
    }

    /// Returns the note's ID.
    pub fn id(&self) -> NoteId {
        match self {
            MockChainNote::Private(id, ..) => *id,
            MockChainNote::Public(note, _) => note.id(),
        }
    }

    /// Returns the underlying note if it is public.
    pub fn note(&self) -> Option<&Note> {
        match self {
            MockChainNote::Private(..) => None,
            MockChainNote::Public(note, _) => Some(note),
        }
    }
}

impl TryFrom<MockChainNote> for InputNote {
    type Error = anyhow::Error;

    fn try_from(value: MockChainNote) -> Result<Self, Self::Error> {
        match value {
            MockChainNote::Private(..) => Err(anyhow::anyhow!(
                "private notes in the mock chain cannot be converted into input notes due to missing details"
            )),
            MockChainNote::Public(note, proof) => Ok(InputNote::Authenticated { note, proof }),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for MockChainNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            MockChainNote::Private(id, metadata, proof) => {
                0u8.write_into(target);
                id.write_into(target);
                metadata.write_into(target);
                proof.write_into(target);
            },
            MockChainNote::Public(note, proof) => {
                1u8.write_into(target);
                note.write_into(target);
                proof.write_into(target);
            },
        }
    }
}

impl Deserializable for MockChainNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note_type = u8::read_from(source)?;
        match note_type {
            0 => {
                let id = NoteId::read_from(source)?;
                let metadata = NoteMetadata::read_from(source)?;
                let proof = NoteInclusionProof::read_from(source)?;
                Ok(MockChainNote::Private(id, metadata, proof))
            },
            1 => {
                let note = Note::read_from(source)?;
                let proof = NoteInclusionProof::read_from(source)?;
                Ok(MockChainNote::Public(note, proof))
            },
            _ => Err(DeserializationError::InvalidValue(format!("Unknown note type: {note_type}"))),
        }
    }
}
