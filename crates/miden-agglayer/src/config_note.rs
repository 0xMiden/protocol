//! CONFIG_AGG_BRIDGE note creation utilities.
//!
//! This module provides helpers for creating CONFIG_AGG_BRIDGE notes,
//! which are used to register faucets in the bridge's faucet registry.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

use miden_assembly::utils::Deserializable;
use miden_core::{Program, Word};
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

// NOTE SCRIPT
// ================================================================================================

// Initialize the CONFIG_AGG_BRIDGE note script only once
static CONFIG_AGG_BRIDGE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/CONFIG_AGG_BRIDGE.masb"));
    let program =
        Program::read_from_bytes(bytes).expect("Shipped CONFIG_AGG_BRIDGE script is well-formed");
    NoteScript::new(program)
});

// CONFIG_AGG_BRIDGE NOTE
// ================================================================================================

/// CONFIG_AGG_BRIDGE note.
///
/// This note is used to register a faucet in the bridge's faucet registry.
/// It carries the faucet account ID and is always public.
pub struct ConfigAggBridgeNote;

impl ConfigAggBridgeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a CONFIG_AGG_BRIDGE note.
    pub const NUM_STORAGE_ITEMS: usize = 2;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the CONFIG_AGG_BRIDGE note script.
    pub fn script() -> NoteScript {
        CONFIG_AGG_BRIDGE_SCRIPT.clone()
    }

    /// Returns the CONFIG_AGG_BRIDGE note script root.
    pub fn script_root() -> Word {
        CONFIG_AGG_BRIDGE_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a CONFIG_AGG_BRIDGE note to register a faucet in the bridge's registry.
    ///
    /// The note storage contains 2 felts:
    /// - `faucet_id_prefix`: The prefix of the faucet account ID
    /// - `faucet_id_suffix`: The suffix of the faucet account ID
    ///
    /// # Parameters
    /// - `faucet_account_id`: The account ID of the faucet to register
    /// - `sender_account_id`: The account ID of the note creator
    /// - `target_account_id`: The bridge account ID that will consume this note
    /// - `rng`: Random number generator for creating the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        faucet_account_id: AccountId,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        // Create note storage with 2 felts: [faucet_id_prefix, faucet_id_suffix]
        let storage_values = vec![faucet_account_id.prefix().as_felt(), faucet_account_id.suffix()];

        let note_storage = NoteStorage::new(storage_values)?;

        // Generate a serial number for the note
        let serial_num = rng.draw_word();

        let recipient = NoteRecipient::new(serial_num, Self::script(), note_storage);

        let attachment = NoteAttachment::from(
            NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
                .map_err(|e| NoteError::other(e.to_string()))?,
        );
        let metadata =
            NoteMetadata::new(sender_account_id, NoteType::Public).with_attachment(attachment);

        // CONFIG_AGG_BRIDGE notes don't carry assets
        let assets = NoteAssets::new(vec![])?;

        Ok(Note::new(assets, metadata, recipient))
    }
}
