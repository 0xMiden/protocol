//! EMERGENCY_PAUSE note creation utilities.
//!
//! This module provides helpers for creating EMERGENCY_PAUSE notes,
//! which are used to set or clear the emergency paused flag on the bridge account.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

use miden_assembly::serde::Deserializable;
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
use miden_protocol::vm::Program;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_utils_sync::LazyLock;

// NOTE SCRIPT
// ================================================================================================

static EMERGENCY_PAUSE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/emergency_pause.masb"));
    let program =
        Program::read_from_bytes(bytes).expect("shipped EMERGENCY_PAUSE script is well-formed");
    NoteScript::new(program)
});

// EMERGENCY_PAUSE NOTE
// ================================================================================================

/// EMERGENCY_PAUSE note.
///
/// This note is used to set or clear the emergency paused flag on the bridge account.
/// It carries a single felt (1 = pause, 0 = unpause) and is always public.
pub struct EmergencyPauseNote;

impl EmergencyPauseNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for an EMERGENCY_PAUSE note.
    pub const NUM_STORAGE_ITEMS: usize = 1;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the EMERGENCY_PAUSE note script.
    pub fn script() -> NoteScript {
        EMERGENCY_PAUSE_SCRIPT.clone()
    }

    /// Returns the EMERGENCY_PAUSE note script root.
    pub fn script_root() -> Word {
        EMERGENCY_PAUSE_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates an EMERGENCY_PAUSE note with the given paused flag.
    ///
    /// # Parameters
    /// - `paused`: true to pause, false to unpause
    /// - `sender_account_id`: The account ID of the note creator (must be bridge admin)
    /// - `target_account_id`: The bridge account ID that will consume this note
    /// - `rng`: Random number generator for creating the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        paused: bool,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let paused_felt = if paused { Felt::ONE } else { Felt::ZERO };
        let note_storage = NoteStorage::new(vec![paused_felt])?;

        let serial_num = rng.draw_word();
        let recipient = NoteRecipient::new(serial_num, Self::script(), note_storage);

        let attachment = NoteAttachment::from(
            NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
                .map_err(|e| NoteError::other(e.to_string()))?,
        );
        let metadata =
            NoteMetadata::new(sender_account_id, NoteType::Public).with_attachment(attachment);

        let assets = NoteAssets::new(vec![])?;

        Ok(Note::new(assets, metadata, recipient))
    }
}
