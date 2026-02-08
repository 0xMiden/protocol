use alloc::vec::Vec;

use miden_core::field::PrimeField64;

use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Felt,
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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA)
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
/// > hash(NOTE_ID || NOTE_METADATA)
///
/// This value is used primarily for authenticating notes consumed when they are consumed
/// in a transaction.
pub fn compute_note_commitment(id: NoteId, metadata: &NoteMetadata) -> Word {
    Hasher::merge(&[id.as_word(), Word::from(metadata)])
}

// CONVERSIONS FROM NOTE HEADER
// ================================================================================================

impl From<NoteHeader> for [Felt; 8] {
    fn from(note_header: NoteHeader) -> Self {
        (&note_header).into()
    }
}

impl From<NoteHeader> for [Word; 2] {
    fn from(note_header: NoteHeader) -> Self {
        (&note_header).into()
    }
}

impl From<NoteHeader> for [u8; 64] {
    fn from(note_header: NoteHeader) -> Self {
        (&note_header).into()
    }
}

impl From<&NoteHeader> for [Felt; 8] {
    fn from(note_header: &NoteHeader) -> Self {
        let mut elements: [Felt; 8] = Default::default();
        elements[..4].copy_from_slice(note_header.note_id.as_elements());
        elements[4..].copy_from_slice(Word::from(note_header.metadata()).as_elements());
        elements
    }
}

impl From<&NoteHeader> for [Word; 2] {
    fn from(note_header: &NoteHeader) -> Self {
        let mut elements: [Word; 2] = Default::default();
        elements[0].copy_from_slice(note_header.note_id.as_elements());
        elements[1].copy_from_slice(Word::from(note_header.metadata()).as_elements());
        elements
    }
}

impl From<&NoteHeader> for [u8; 64] {
    fn from(note_header: &NoteHeader) -> Self {
        let mut elements: [u8; 64] = [0; 64];
        let note_metadata_bytes = Word::from(note_header.metadata())
            .iter()
            .flat_map(|x| x.as_canonical_u64().to_le_bytes())
            .collect::<Vec<u8>>();
        elements[..32].copy_from_slice(&note_header.note_id.as_bytes());
        elements[32..].copy_from_slice(&note_metadata_bytes);
        elements
    }
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
