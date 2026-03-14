use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteAssets,
    NoteHeader,
    NoteId,
    NoteMetadata,
    Serializable,
};
use crate::Word;

// PARTIAL NOTE
// ================================================================================================

/// Partial information about a note.
///
/// Partial note consists of [NoteMetadata], [NoteAssets], and a recipient digest (see
/// [super::NoteRecipient]). However, it does not contain detailed recipient info, including
/// note script, note storage, and note's serial number. This means that a partial note is
/// sufficient to compute note ID and note header, but not sufficient to compute note nullifier,
/// and generally does not have enough info to execute the note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialNote {
    header: NoteHeader,
    recipient_digest: Word,
    assets: NoteAssets,
}

impl PartialNote {
    /// Returns a new [PartialNote] instantiated from the provided parameters.
    pub fn new(metadata: NoteMetadata, recipient_digest: Word, assets: NoteAssets) -> Self {
        let note_id = NoteId::new(recipient_digest, assets.commitment());
        let header = NoteHeader::new(note_id, metadata);
        Self { header, recipient_digest, assets }
    }

    /// Returns the ID corresponding to this note.
    pub fn id(&self) -> NoteId {
        NoteId::new(self.recipient_digest, self.assets.commitment())
    }

    /// Returns the metadata associated with this note.
    pub fn metadata(&self) -> &NoteMetadata {
        self.header.metadata()
    }

    /// Returns the digest of the recipient associated with this note.
    ///
    /// See [super::NoteRecipient] for more info.
    pub fn recipient_digest(&self) -> Word {
        self.recipient_digest
    }

    /// Returns a list of assets associated with this note.
    pub fn assets(&self) -> &NoteAssets {
        &self.assets
    }

    /// Returns the [`NoteHeader`] of this note.
    pub fn header(&self) -> &NoteHeader {
        &self.header
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Serialize only metadata since the note ID in the header can be recomputed from the
        // remaining data.
        self.header().metadata().write_into(target);
        self.recipient_digest.write_into(target);
        self.assets.write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        self.metadata().get_size_hint() + Word::SERIALIZED_SIZE + self.assets.get_size_hint()
    }
}

impl Deserializable for PartialNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let metadata = NoteMetadata::read_from(source)?;
        let recipient_digest = Word::read_from(source)?;
        let assets = NoteAssets::read_from(source)?;

        Ok(Self::new(metadata, recipient_digest, assets))
    }
}
