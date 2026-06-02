//! Bridge Message note creation utilities.
//!
//! This module provides helpers for creating Bridge Message notes,
//! which are used to send cross-chain messages (without assets) via the AggLayer network.

use alloc::vec::Vec;

use miden_assembly::Library;
use miden_assembly::serde::Deserializable;
use miden_core::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteAttachments,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_utils_sync::LazyLock;

use crate::{EthAddress, MetadataHash};

// NOTE SCRIPT
// ================================================================================================

// Initialize the Bridge Message note script only once
static BRIDGE_MESSAGE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/bridge_message.masl"));
    let library = Library::read_from_bytes(bytes)
        .expect("shipped Bridge Message script library is well-formed");
    NoteScript::from_library(&library).expect("shipped Bridge Message script is well-formed")
});

// MESSAGE NOTE
// ================================================================================================

/// Bridge Message note.
///
/// This note is used to send a cross-chain message from Miden to another network via the AggLayer.
/// Unlike B2AGG notes, message notes carry no assets — they only convey routing information
/// (destination network, destination address) and an arbitrary metadata hash.
/// Message notes are always public.
pub struct MessageNote;

impl MessageNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a Bridge Message note.
    /// Layout: 1 (destination_network) + 5 (destination_address) + 8 (metadata_hash) = 14
    pub const NUM_STORAGE_ITEMS: usize = 14;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the Bridge Message note script.
    pub fn script() -> NoteScript {
        BRIDGE_MESSAGE_SCRIPT.clone()
    }

    /// Returns the Bridge Message note script root.
    pub fn script_root() -> NoteScriptRoot {
        BRIDGE_MESSAGE_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a Bridge Message note.
    ///
    /// This note is used to send a cross-chain message from Miden to another network via the
    /// AggLayer. When consumed by a bridge account, the message metadata is forwarded to the
    /// destination network. Message notes carry no assets and are always public.
    ///
    /// # Parameters
    /// - `destination_network`: The AggLayer-assigned network ID for the destination chain
    /// - `destination_address`: The Ethereum address on the destination network
    /// - `metadata_hash`: The hash of the message metadata
    /// - `target_account_id`: The account ID that will consume this note (bridge account)
    /// - `sender_account_id`: The account ID of the note creator
    /// - `rng`: Random number generator for creating the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        destination_network: u32,
        destination_address: EthAddress,
        metadata_hash: MetadataHash,
        target_account_id: AccountId,
        sender_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_storage =
            build_note_storage(destination_network, destination_address, metadata_hash)?;

        let attachment = NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
            .map_err(|error| {
                NoteError::other_with_source(
                    "failed to create bridge message network account target",
                    error,
                )
            })?;
        let attachments = NoteAttachments::from(NoteAttachment::from(attachment));

        let metadata = PartialNoteMetadata::new(sender_account_id, NoteType::Public);

        let recipient = NoteRecipient::new(rng.draw_word(), Self::script(), note_storage);

        let assets = NoteAssets::default();

        Ok(Note::with_attachments(assets, metadata, recipient, attachments))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds the note storage for a Bridge Message note.
///
/// The storage layout is:
/// - 1 felt: destination_network (byte-swapped to LE u32, matching the leaf data convention)
/// - 5 felts: destination_address (20 bytes as 5 LE-packed u32 values)
/// - 8 felts: metadata_hash (32 bytes as 8 LE-packed u32 values)
fn build_note_storage(
    destination_network: u32,
    destination_address: EthAddress,
    metadata_hash: MetadataHash,
) -> Result<NoteStorage, NoteError> {
    let mut elements = Vec::with_capacity(14);

    let destination_network = u32::from_le_bytes(destination_network.to_be_bytes());
    elements.push(Felt::from(destination_network));
    elements.extend(destination_address.to_elements());
    elements.extend(metadata_hash.to_elements());

    NoteStorage::new(elements)
}
