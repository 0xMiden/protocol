//! PAUSE_AGG_BRIDGE note creation utilities.
//!
//! This module provides helpers for creating PAUSE_AGG_BRIDGE notes, which toggle the bridge
//! account's emergency pause. The note wraps the standards `PausableManager` `pause` / `unpause`
//! dispatch in an agglayer note script that - like every other bridge admin note - asserts the
//! `NetworkAccountTarget` attachment, so the note is bound to a specific bridge account and is
//! routable as a network note.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

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
use miden_standards::note::costs::NoteConsumptionCost;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint, PauseAction};
use miden_utils_sync::LazyLock;

use crate::costs::PAUSE_AGG_BRIDGE_CONSUMPTION_CYCLES;
use crate::note_script;

// NOTE SCRIPT
// ================================================================================================

/// Path to the PAUSE_AGG_BRIDGE note script procedure in the agglayer package.
const PAUSE_AGG_BRIDGE_SCRIPT_PATH: &str = "::agglayer::notes::pause_agg_bridge::main";

// Initialize the PAUSE_AGG_BRIDGE note script only once
static PAUSE_AGG_BRIDGE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| note_script(PAUSE_AGG_BRIDGE_SCRIPT_PATH));

// PAUSE_AGG_BRIDGE NOTE
// ================================================================================================

/// PAUSE_AGG_BRIDGE note.
///
/// This note toggles the bridge account's emergency pause by dispatching to the standards
/// `PausableManager` `pause` / `unpause` procedures, selected by a [`PauseAction`] stored in the
/// single note storage item. Authorization is enforced by those procedures via the account-wide
/// `Authority` component (the `ADMIN` role on the bridge); the script additionally asserts the
/// `NetworkAccountTarget` attachment so the note cannot be consumed by any other account.
pub struct PauseAggBridgeNote;

impl PauseAggBridgeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a PAUSE_AGG_BRIDGE note.
    pub const NUM_STORAGE_ITEMS: usize = 1;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the PAUSE_AGG_BRIDGE note script.
    pub fn script() -> NoteScript {
        PAUSE_AGG_BRIDGE_SCRIPT.clone()
    }

    /// Returns the PAUSE_AGG_BRIDGE note script root.
    pub fn script_root() -> NoteScriptRoot {
        PAUSE_AGG_BRIDGE_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a PAUSE_AGG_BRIDGE note for the given action.
    ///
    /// The note storage contains a single felt: the action selector.
    ///
    /// # Parameters
    /// - `action`: whether to pause or unpause the bridge
    /// - `sender_account_id`: the account ID of the note creator (must hold the bridge's `ADMIN`
    ///   role for the note to be consumable)
    /// - `target_account_id`: the account ID that will consume this note (the bridge account)
    /// - `rng`: random number generator for the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        action: PauseAction,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_storage = NoteStorage::from(action);

        let serial_num = rng.draw_word();
        let recipient = NoteRecipient::new(serial_num, Self::script(), note_storage);

        let attachment = NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
            .map_err(|e| NoteError::other(e.to_string()))?;
        let attachments = NoteAttachments::from(NoteAttachment::from(attachment));
        let metadata = PartialNoteMetadata::new(sender_account_id, NoteType::Public);

        // PAUSE_AGG_BRIDGE notes don't carry assets
        let assets = NoteAssets::new(vec![])?;

        Ok(Note::with_attachments(assets, metadata, recipient, attachments))
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for PauseAggBridgeNote {
    fn consumption_cycles() -> u32 {
        PAUSE_AGG_BRIDGE_CONSUMPTION_CYCLES
    }
}
