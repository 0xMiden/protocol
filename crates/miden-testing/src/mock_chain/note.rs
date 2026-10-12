use miden_objects::{Verify, proto};
use miden_protocol::note::{Note, NoteAttachments, NoteId, NoteInclusionProof, NoteMetadata};
use miden_protocol::transaction::{InputNote, PrivateOutputNote};
use proto::mock_chain as wire;

// MOCK CHAIN NOTE
// ================================================================================================

/// Represents a note that is stored in the mock chain.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockChainNote {
    /// Contains the [`PrivateOutputNote`] alongside its [`NoteInclusionProof`]. Other details
    /// needed to consume the note are expected to be stored locally, off-chain.
    Private(PrivateOutputNote, NoteInclusionProof),
    /// Contains the full [`Note`] object alongside its [`NoteInclusionProof`].
    Public(Note, NoteInclusionProof),
}

impl MockChainNote {
    /// Returns the note's inclusion details.
    pub fn inclusion_proof(&self) -> &NoteInclusionProof {
        match self {
            MockChainNote::Private(_, inclusion_proof)
            | MockChainNote::Public(_, inclusion_proof) => inclusion_proof,
        }
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        match self {
            MockChainNote::Private(note, _) => note.metadata(),
            MockChainNote::Public(note, _) => note.metadata(),
        }
    }

    /// Returns the note's attachments.
    pub fn attachments(&self) -> &NoteAttachments {
        match self {
            MockChainNote::Private(note, _) => note.attachments(),
            MockChainNote::Public(note, _) => note.attachments(),
        }
    }

    /// Returns the note's ID.
    pub fn id(&self) -> NoteId {
        match self {
            MockChainNote::Private(note, _) => note.id(),
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

    /// Encodes a committed note for a local mock chain snapshot.
    pub(super) fn encode(&self) -> wire::MockChainNote {
        use wire::mock_chain_note::Note;

        let note = match self {
            Self::Public(note, _) => Note::Public(note.into()),
            Self::Private(note, _) => Note::Private(note.into()),
        };
        wire::MockChainNote {
            proof: Some((&self.id(), self.inclusion_proof()).into()),
            note: Some(note),
        }
    }

    /// Restores a committed note from a trusted local mock chain snapshot.
    pub(super) fn decode(note: wire::DecodedMockChainNote) -> anyhow::Result<Self> {
        use wire::mock_chain_note::DecodedNote;

        let (_, proof) = note.proof.verify()?;
        match note.note {
            DecodedNote::Public(note) => Ok(Self::Public(note.verify()?, proof)),
            DecodedNote::Private(note) => Ok(Self::Private(note.verify()?, proof)),
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
