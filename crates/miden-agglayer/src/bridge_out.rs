//! Bridge Out note creation utilities.
//!
//! This module provides helpers for creating B2AGG (Bridge to AggLayer) notes,
//! which are used to bridge assets out from Miden to the AggLayer network.

use alloc::string::ToString;
use alloc::vec::Vec;

use miden_core::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteExecutionHint,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_standards::note::NetworkAccountTarget;

use crate::{EthAddressFormat, b2agg_script};

// B2AGG NOTE STRUCTURES
// ================================================================================================

/// Storage data for B2AGG note creation.
///
/// Contains the destination network and address, required for bridging assets to AggLayer.
#[derive(Debug, Clone)]
pub struct B2AggNoteStorage {
    /// Destination network identifier (AggLayer-assigned network ID)
    pub destination_network: u32,
    /// Destination Ethereum address (20 bytes)
    pub destination_address: EthAddressFormat,
}

impl B2AggNoteStorage {
    /// Creates a new B2AGG note storage with the specified destination.
    pub fn new(destination_network: u32, destination_address: EthAddressFormat) -> Self {
        Self { destination_network, destination_address }
    }

    /// Converts the storage data to a vector of field elements for note storage.
    ///
    /// The layout is:
    /// - 1 felt: destination_network
    /// - 5 felts: destination_address (20 bytes as 5 u32 values)
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(6);

        // Destination network
        elements.push(Felt::new(self.destination_network as u64));

        // Destination address (5 u32 felts)
        elements.extend(self.destination_address.to_elements());

        elements
    }
}

impl TryFrom<B2AggNoteStorage> for NoteStorage {
    type Error = NoteError;

    fn try_from(storage: B2AggNoteStorage) -> Result<Self, Self::Error> {
        NoteStorage::new(storage.to_elements())
    }
}

// B2AGG NOTE CREATION
// ================================================================================================

/// Generates a B2AGG (Bridge to AggLayer) note.
///
/// This note is used to bridge assets from Miden to another network via the AggLayer.
/// When consumed by a bridge account, the assets are burned and a corresponding
/// claim can be made on the destination network. B2AGG notes are always public.
///
/// # Parameters
/// - `storage`: The destination network and address information
/// - `assets`: The assets to bridge (must be fungible assets from a network faucet)
/// - `target_account_id`: The account ID that will consume this note (bridge account)
/// - `sender_account_id`: The account ID of the note creator
/// - `rng`: Random number generator for creating the note serial number
///
/// # Errors
/// Returns an error if note creation fails.
pub fn create_b2agg_note<R: FeltRng>(
    storage: B2AggNoteStorage,
    assets: NoteAssets,
    target_account_id: AccountId,
    sender_account_id: AccountId,
    rng: &mut R,
) -> Result<Note, NoteError> {
    let note_storage = NoteStorage::try_from(storage)?;

    let tag = NoteTag::new(0);

    let attachment = NoteAttachment::from(
        NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
            .map_err(|e| NoteError::other(e.to_string()))?,
    );

    let metadata =
        NoteMetadata::new(sender_account_id, NoteType::Public, tag).with_attachment(attachment);

    let b2agg_script = b2agg_script();
    let recipient =
        NoteRecipient::new(rng.draw_word(), NoteScript::new(b2agg_script), note_storage);

    Ok(Note::new(assets, metadata, recipient))
}
