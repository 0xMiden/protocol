use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteAssets,
    NoteAttachments,
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
/// Partial note consists of [NoteMetadata], [NoteAssets], [NoteAttachments], and a recipient digest
/// (see [super::NoteRecipient]). However, it does not contain detailed recipient info, including
/// note script, note storage, and note's serial number. This means that a partial note is
/// sufficient to compute note ID and note header, but not sufficient to compute note nullifier,
/// and generally does not have enough info to execute the note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialNote {
    header: NoteHeader,
    recipient_digest: Word,
    assets: NoteAssets,
    attachments: NoteAttachments,
}

impl PartialNote {
    /// Returns a new [PartialNote] instantiated from the provided parameters.
    pub fn new(
        metadata: NoteMetadata,
        recipient_digest: Word,
        assets: NoteAssets,
        attachments: NoteAttachments,
    ) -> Self {
        let note_id = NoteId::new(recipient_digest, assets.commitment());
        let metadata = metadata.with_attachments(&attachments);
        let header = NoteHeader::new(note_id, metadata);
        Self {
            header,
            recipient_digest,
            assets,
            attachments,
        }
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

    /// Returns the note's attachments.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }

    /// Returns the [`NoteHeader`] of this note.
    pub fn header(&self) -> &NoteHeader {
        &self.header
    }

    /// Consumes self and returns the non-Copy parts of this note.
    pub fn into_parts(self) -> (NoteAssets, NoteHeader, NoteAttachments) {
        (self.assets, self.header, self.attachments)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // The metadata's attachment headers and commitment are derivable from `attachments`, so
        // only the user-facing metadata fields are written here. Note ID can be recomputed from
        // the remaining data.
        self.header().metadata().write_core(target);
        self.recipient_digest.write_into(target);
        self.assets.write_into(target);
        self.attachments.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        let metadata = self.metadata();
        metadata.sender().get_size_hint()
            + metadata.note_type().get_size_hint()
            + metadata.tag().get_size_hint()
            + Word::SERIALIZED_SIZE
            + self.assets.get_size_hint()
            + self.attachments.get_size_hint()
    }
}

impl Deserializable for PartialNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let (sender, note_type, tag) = NoteMetadata::read_core(source)?;
        let metadata = NoteMetadata::new(sender, note_type).with_tag(tag);
        let recipient_digest = Word::read_from(source)?;
        let assets = NoteAssets::read_from(source)?;
        let attachments = NoteAttachments::read_from(source)?;

        Ok(Self::new(metadata, recipient_digest, assets, attachments))
    }
}
