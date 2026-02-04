use miden_protocol::asset::Asset;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteMetadata,
    NoteRecipient,
    PartialNote,
};

use super::{OutputNote, Word};
use crate::errors::TransactionKernelError;

// OUTPUT NOTE BUILDER
// ================================================================================================

/// Builder of an output note, provided primarily to enable adding assets to a note incrementally.
#[derive(Debug, Clone)]
pub struct OutputNoteBuilder {
    metadata: NoteMetadata,
    assets: NoteAssets,
    recipient_digest: Word,
    recipient: Option<NoteRecipient>,
}

impl OutputNoteBuilder {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [OutputNoteBuilder] from the provided metadata, recipient digest, and optional
    /// recipient.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the note is public.
    pub fn from_recipient_digest(
        metadata: NoteMetadata,
        recipient_digest: Word,
    ) -> Result<Self, TransactionKernelError> {
        // For public notes, we must have a recipient.
        if !metadata.is_private() {
            return Err(TransactionKernelError::PublicNoteMissingDetails(
                metadata,
                recipient_digest,
            ));
        }

        Ok(Self {
            metadata,
            recipient_digest,
            recipient: None,
            assets: NoteAssets::default(),
        })
    }

    /// Returns a new [`OutputNoteBuilder`] from the provided metadata and recipient.
    pub fn from_recipient(metadata: NoteMetadata, recipient: NoteRecipient) -> Self {
        Self {
            metadata,
            recipient_digest: recipient.digest(),
            recipient: Some(recipient),
            assets: NoteAssets::default(),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the specified asset to the note.
    ///
    /// # Errors
    /// Returns an error if adding the asset to the note fails. This can happen for the following
    /// reasons:
    /// - The same non-fungible asset is already added to the note.
    /// - A fungible asset issued by the same faucet is already added to the note and adding both
    ///   assets together results in an invalid asset.
    /// - Adding the asset to the note will push the list beyond the [NoteAssets::MAX_NUM_ASSETS]
    ///   limit.
    pub fn add_asset(&mut self, asset: Asset) -> Result<(), TransactionKernelError> {
        self.assets
            .add_asset(asset)
            .map_err(TransactionKernelError::FailedToAddAssetToNote)?;
        Ok(())
    }

    /// Overwrites the attachment in the note's metadata.
    pub fn set_attachment(&mut self, attachment: NoteAttachment) {
        self.metadata.set_attachment(attachment);
    }

    /// Converts this builder to an [OutputNote].
    ///
    /// Depending on the available information, this may result in [OutputNote::Full] or
    /// [OutputNote::Partial] notes.
    pub fn build(self) -> OutputNote {
        match self.recipient {
            Some(recipient) => {
                let note = Note::new(self.assets, self.metadata, recipient);
                OutputNote::Full(note)
            },
            None => {
                let note = PartialNote::new(self.metadata, self.recipient_digest, self.assets);
                OutputNote::Partial(note)
            },
        }
    }
}
