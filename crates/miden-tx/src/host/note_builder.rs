use alloc::vec::Vec;

use miden_protocol::asset::Asset;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteMetadata,
    NoteRecipient,
    PartialNote,
};

use super::{RawOutputNote, Word};
use crate::errors::TransactionKernelError;

// OUTPUT NOTE BUILDER
// ================================================================================================

/// Builder of an output note, provided primarily to enable adding assets to a note incrementally.
///
/// Assets are accumulated in a `Vec` and the final `NoteAssets` is only constructed when
/// [`build`](Self::build) is called. This avoids recomputing the commitment hash on every asset
/// addition.
#[derive(Debug, Clone)]
pub struct OutputNoteBuilder {
    metadata: NoteMetadata,
    assets: Vec<Asset>,
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
            assets: Vec::new(),
        })
    }

    /// Returns a new [`OutputNoteBuilder`] from the provided metadata and recipient.
    pub fn from_recipient(metadata: NoteMetadata, recipient: NoteRecipient) -> Self {
        Self {
            metadata,
            recipient_digest: recipient.digest(),
            recipient: Some(recipient),
            assets: Vec::new(),
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
        // Check if an asset issued by the same faucet already exists in the list of assets.
        if let Some(own_asset) = self.assets.iter_mut().find(|a| a.is_same(&asset)) {
            match own_asset {
                Asset::Fungible(f_own_asset) => {
                    // If a fungible asset issued by the same faucet is found, try to add the
                    // provided asset to it.
                    let new_asset = f_own_asset
                        .add(asset.unwrap_fungible())
                        .map_err(NoteError::AddFungibleAssetBalanceError)
                        .map_err(TransactionKernelError::FailedToAddAssetToNote)?;
                    *own_asset = Asset::Fungible(new_asset);
                },
                Asset::NonFungible(nf_asset) => {
                    return Err(TransactionKernelError::FailedToAddAssetToNote(
                        NoteError::DuplicateNonFungibleAsset(*nf_asset),
                    ));
                },
            }
        } else {
            // If the asset is not in the list, add it to the list.
            self.assets.push(asset);
            if self.assets.len() > NoteAssets::MAX_NUM_ASSETS {
                return Err(TransactionKernelError::FailedToAddAssetToNote(
                    NoteError::TooManyAssets(self.assets.len()),
                ));
            }
        }

        Ok(())
    }

    /// Overwrites the attachment in the note's metadata.
    pub fn set_attachment(&mut self, attachment: NoteAttachment) {
        self.metadata.set_attachment(attachment);
    }

    /// Converts this builder to an [OutputNote].
    ///
    /// Depending on the available information, this may result in [`OutputNote::Full`] or
    /// [`OutputNote::Partial`] notes.
    pub fn build(self) -> RawOutputNote {
        let assets = NoteAssets::new(self.assets)
            .expect("assets should be valid since add_asset validates them");

        match self.recipient {
            Some(recipient) => {
                let note = Note::new(assets, self.metadata, recipient);
                RawOutputNote::Full(note)
            },
            None => {
                let note = PartialNote::new(self.metadata, self.recipient_digest, assets);
                RawOutputNote::Partial(note)
            },
        }
    }
}
