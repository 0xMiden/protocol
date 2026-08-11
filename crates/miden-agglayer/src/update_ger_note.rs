//! UPDATE_GER note creation utilities.
//!
//! This module provides helpers for creating UPDATE_GER notes,
//! which are used to update the Global Exit Root in the bridge account.

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_standards::note::costs::NoteConsumptionCost;
use miden_utils_sync::LazyLock;

use crate::costs::UPDATE_GER_CONSUMPTION_CYCLES;
use crate::ger_note::create_ger_note;
use crate::{ExitRoot, note_script};

// NOTE SCRIPT
// ================================================================================================

/// Path to the UPDATE_GER note script procedure in the agglayer package.
const UPDATE_GER_SCRIPT_PATH: &str = "::agglayer::notes::update_ger::main";

// Initialize the UPDATE_GER note script only once
static UPDATE_GER_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| note_script(UPDATE_GER_SCRIPT_PATH));

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
    pub fn script_root() -> NoteScriptRoot {
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
        create_ger_note(ger, sender_account_id, target_account_id, Self::script(), rng)
    }
}

// NOTE CONSUMPTION COST
// ================================================================================================

impl NoteConsumptionCost for UpdateGerNote {
    fn consumption_cycles() -> u32 {
        UPDATE_GER_CONSUMPTION_CYCLES
    }
}
