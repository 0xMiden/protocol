use super::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    NoteAssets,
    NoteAttachments,
    NoteDetailsCommitment,
    NoteHeader,
    NoteId,
    NoteMetadata,
    PartialNoteMetadata,
    Serializable,
};
use crate::Word;

// PARTIAL NOTE
// ================================================================================================

/// A note without detailed recipient information.
///
/// A partial note consists of [`PartialNoteMetadata`], [`NoteAssets`], [`NoteAttachments`], and a
/// commitment to the [`NoteRecipient`](super::NoteRecipient)). However, it does not contain
/// the full recipient, including note script, note storage, and note's serial number. This
/// means that a partial note is sufficient to compute note ID and note header, but not sufficient
/// to compute note nullifier, and generally does not have enough info to execute the note.
///
/// One use case for the [`PartialNote`] is to return the details of a private note created during a
/// transaction, where the assets and attachments are known, but the recipient is not.
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
        partial_metadata: PartialNoteMetadata,
        recipient_digest: Word,
        assets: NoteAssets,
        attachments: NoteAttachments,
    ) -> Self {
        let details_commitment = NoteDetailsCommitment::new(recipient_digest, assets.commitment());
        let metadata = NoteMetadata::new(partial_metadata, &attachments);
        let header = NoteHeader::new(details_commitment, metadata);
        Self {
            header,
            recipient_digest,
            assets,
            attachments,
        }
    }

    /// Returns the ID corresponding to this note.
    pub fn id(&self) -> NoteId {
        self.header.id()
    }

    /// Returns the commitment to the note details, excluding metadata.
    pub fn commitment(&self) -> NoteDetailsCommitment {
        self.header.commitment()
    }

    /// Returns a reference to the [`NoteMetadata`] of this note.
    pub fn metadata(&self) -> &NoteMetadata {
        self.header.metadata()
    }

    /// Returns the partial metadata associated with this note.
    pub fn partial_metadata(&self) -> &PartialNoteMetadata {
        self.header.metadata().partial_metadata()
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
        // Serialize only partial metadata since note ID can be recomputed from the note details and
        // attachment schemes and commitments can be reconstructed from attachments
        self.header().metadata().partial_metadata().write_into(target);
        self.recipient_digest.write_into(target);
        self.assets.write_into(target);
        self.attachments.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.partial_metadata().get_size_hint()
            + Word::SERIALIZED_SIZE
            + self.assets.get_size_hint()
            + self.attachments.get_size_hint()
    }
}

impl Deserializable for PartialNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let partial_metadata = PartialNoteMetadata::read_from(source)?;
        let recipient_digest = Word::read_from(source)?;
        let assets = NoteAssets::read_from(source)?;
        let attachments = NoteAttachments::read_from(source)?;

        Ok(Self::new(partial_metadata, recipient_digest, assets, attachments))
    }
}
