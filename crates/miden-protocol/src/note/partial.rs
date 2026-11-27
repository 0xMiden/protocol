use super::{
    NoteAssets,
    NoteAttachments,
    NoteDetailsCommitment,
    NoteHeader,
    NoteId,
    NoteMetadata,
    PartialNoteMetadata,
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
        let details_commitment =
            NoteDetailsCommitment::from_raw_commitments(recipient_digest, assets.commitment());
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

    /// Returns the commitment to the note's details, excluding metadata.
    pub fn details_commitment(&self) -> NoteDetailsCommitment {
        self.header.details_commitment()
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
