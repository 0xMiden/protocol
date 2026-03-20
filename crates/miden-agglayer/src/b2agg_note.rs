//! Bridge Out note creation utilities.
//!
//! This module provides helpers for creating B2AGG (Bridge to AggLayer) notes,
//! which are used to bridge assets out from Miden to the AggLayer network.

use alloc::string::ToString;
use alloc::vec::Vec;

use miden_assembly::serde::Deserializable;
use miden_core::program::Program;
use miden_core::{Felt, Word};
use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteAttachment,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteType,
};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_utils_sync::LazyLock;

use crate::EthAddress;

// NOTE SCRIPT
// ================================================================================================

// Initialize the B2AGG note script only once
static B2AGG_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/B2AGG.masb"));
    let program = Program::read_from_bytes(bytes).expect("shipped B2AGG script is well-formed");
    NoteScript::new(program)
});

// B2AGG NOTE
// ================================================================================================

/// B2AGG (Bridge to AggLayer) note.
///
/// This note is used to bridge assets from Miden to another network via the AggLayer.
/// When consumed by a bridge account, the assets are burned and a corresponding
/// claim can be made on the destination network. B2AGG notes are always public.
pub struct B2AggNote;

impl B2AggNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a B2AGG note.
    pub const NUM_STORAGE_ITEMS: usize = 6;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the B2AGG (Bridge to AggLayer) note script.
    pub fn script() -> NoteScript {
        B2AGG_SCRIPT.clone()
    }

    /// Returns the B2AGG note script root.
    pub fn script_root() -> Word {
        B2AGG_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a B2AGG (Bridge to AggLayer) note.
    ///
    /// This note is used to bridge assets from Miden to another network via the AggLayer.
    /// When consumed by a bridge account, the assets are burned and a corresponding
    /// claim can be made on the destination network. B2AGG notes are always public.
    ///
    /// # Parameters
    /// - `destination_network`: The AggLayer-assigned network ID for the destination chain
    /// - `destination_address`: The Ethereum address on the destination network
    /// - `assets`: The assets to bridge (must be fungible assets from a network faucet)
    /// - `target_account_id`: The account ID that will consume this note (bridge account)
    /// - `sender_account_id`: The account ID of the note creator
    /// - `rng`: Random number generator for creating the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        destination_network: u32,
        destination_address: EthAddress,
        assets: NoteAssets,
        target_account_id: AccountId,
        sender_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_storage = build_note_storage(destination_network, destination_address)?;

        let attachment = NoteAttachment::from(
            NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
                .map_err(|e| NoteError::other(e.to_string()))?,
        );

        let metadata =
            NoteMetadata::new(sender_account_id, NoteType::Public).with_attachment(attachment);

        let recipient = NoteRecipient::new(rng.draw_word(), Self::script(), note_storage);

        Ok(Note::new(assets, metadata, recipient))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds the note storage for a B2AGG note.
///
/// The storage layout is:
/// - 1 felt: destination_network
/// - 5 felts: destination_address (20 bytes as 5 u32 values)
fn build_note_storage(
    destination_network: u32,
    destination_address: EthAddress,
) -> Result<NoteStorage, NoteError> {
    let mut elements = Vec::with_capacity(6);

    let destination_network = u32::from_le_bytes(destination_network.to_be_bytes());
    elements.push(Felt::from(destination_network));
    elements.extend(destination_address.to_elements());

    NoteStorage::new(elements)
}
