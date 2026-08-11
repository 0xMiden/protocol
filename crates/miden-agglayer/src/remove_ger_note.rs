//! REMOVE_GER note creation utilities.
//!
//! This module provides helpers for creating REMOVE_GER notes,
//! which are used to remove a Global Exit Root from the bridge account and fold it into the
//! running removed-GER keccak256 hash chain.

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_standards::note::costs::NoteConsumptionCost;
use miden_utils_sync::LazyLock;

use crate::costs::REMOVE_GER_CONSUMPTION_CYCLES;
use crate::ger_note::create_ger_note;
use crate::{ExitRoot, note_script};

// NOTE SCRIPT
// ================================================================================================

/// Path to the REMOVE_GER note script procedure in the agglayer package.
const REMOVE_GER_SCRIPT_PATH: &str = "::agglayer::notes::remove_ger::main";

// Initialize the REMOVE_GER note script only once
static REMOVE_GER_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| note_script(REMOVE_GER_SCRIPT_PATH));

// REMOVE_GER NOTE
// ================================================================================================

/// REMOVE_GER note.
///
/// This note is used to remove a Global Exit Root (GER) from the bridge account and fold it into
/// the running removed-GER keccak256 hash chain. It carries the GER data and is always public.
pub struct RemoveGerNote;

impl RemoveGerNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a REMOVE_GER note.
    pub const NUM_STORAGE_ITEMS: usize = 8;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the REMOVE_GER note script.
    pub fn script() -> NoteScript {
        REMOVE_GER_SCRIPT.clone()
    }

    /// Returns the REMOVE_GER note script root.
    pub fn script_root() -> NoteScriptRoot {
        REMOVE_GER_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a REMOVE_GER note with the given GER (Global Exit Root) data.
    ///
    /// The note storage contains 8 felts: GER[0..7]
    ///
    /// # Parameters
    /// - `ger`: The Global Exit Root data to remove
    /// - `sender_account_id`: The account ID of the note creator (must be the GER remover)
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

impl NoteConsumptionCost for RemoveGerNote {
    fn consumption_cycles() -> u32 {
        REMOVE_GER_CONSUMPTION_CYCLES
    }
}
