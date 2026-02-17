//! UPDATE_GER note creation utilities.
//!
//! This module provides helpers for creating UPDATE_GER notes,
//! which are used to update the Global Exit Root in the bridge account.

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

use crate::ExitRoot;

// NOTE SCRIPT
// ================================================================================================

// Initialize the UPDATE_GER note script only once
static UPDATE_GER_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/UPDATE_GER.masb"));
    let program =
        Program::read_from_bytes(bytes).expect("Shipped UPDATE_GER script is well-formed");
    NoteScript::new(program)
});

// UPDATE_GER NOTE
// ================================================================================================

/// UPDATE_GER note.
///
/// This note is used to update the Global Exit Root (GER) in the bridge account.
/// It carries the new GER data and is always public.
pub struct UpdateGerNote;

impl UpdateGerNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for an UPDATE_GER note.
    pub const NUM_STORAGE_ITEMS: usize = 8;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the UPDATE_GER note script.
    pub fn script() -> NoteScript {
        UPDATE_GER_SCRIPT.clone()
    }

    /// Returns the UPDATE_GER note script root.
    pub fn script_root() -> Word {
        UPDATE_GER_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates an UPDATE_GER note with the given GER (Global Exit Root) data.
    ///
    /// The note storage contains 8 felts: GER[0..7]
    ///
    /// # Parameters
    /// - `ger`: The Global Exit Root data
    /// - `sender_account_id`: The account ID of the note creator
    /// - `target_account_id`: The account ID that will consume this note (bridge account)
    /// - `rng`: Random number generator for creating the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        ger: ExitRoot,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        // Create note storage with 8 felts: GER[0..7]
        let storage_values = ger.to_elements().to_vec();

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

        // UPDATE_GER notes don't carry assets
        let assets = NoteAssets::new(vec![])?;

        Ok(Note::new(assets, metadata, recipient))
    }
}
