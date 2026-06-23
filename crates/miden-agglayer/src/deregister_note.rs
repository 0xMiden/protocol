//! DEREGISTER_AGG_FAUCET note creation utilities.
//!
//! This module provides helpers for creating DEREGISTER_AGG_FAUCET notes,
//! which are used to deregister faucets from the bridge's faucet registry.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
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

// NOTE SCRIPT
// ================================================================================================

// Initialize the DEREGISTER_AGG_FAUCET note script only once
static DEREGISTER_AGG_FAUCET_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/deregister_agg_faucet.masl"));
    let library = Library::read_from_bytes(bytes)
        .expect("shipped DEREGISTER_AGG_FAUCET script library is well-formed");
    NoteScript::from_library(&library).expect("shipped DEREGISTER_AGG_FAUCET script is well-formed")
});

// DEREGISTER_AGG_FAUCET NOTE
// ================================================================================================

/// DEREGISTER_AGG_FAUCET note.
///
/// This note is used to deregister a faucet from the bridge's faucet registry, token registry,
/// and faucet metadata. It carries only the faucet account ID; the bridge reads the registered
/// origin token address and origin network back from its own faucet metadata, so the token
/// registry key it clears matches the faucet's current registration rather than trusting
/// note-supplied values. The note is always public.
///
/// Note that any in-flight notes (B2AGG / CLAIM) targeting the deregistered faucet will fail
/// after this note is consumed, since `assert_faucet_registered` and
/// `lookup_faucet_by_token_address` will no longer find the faucet.
pub struct DeregisterAggFaucetNote;

impl DeregisterAggFaucetNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a DEREGISTER_AGG_FAUCET note.
    /// Layout: [faucet_id_suffix, faucet_id_prefix]
    pub const NUM_STORAGE_ITEMS: usize = 2;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the DEREGISTER_AGG_FAUCET note script.
    pub fn script() -> NoteScript {
        DEREGISTER_AGG_FAUCET_SCRIPT.clone()
    }

    /// Returns the DEREGISTER_AGG_FAUCET note script root.
    pub fn script_root() -> NoteScriptRoot {
        DEREGISTER_AGG_FAUCET_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a DEREGISTER_AGG_FAUCET note to deregister a faucet from the bridge's registry.
    ///
    /// The note storage contains 2 felts:
    /// - `faucet_id_suffix`: The suffix of the faucet account ID
    /// - `faucet_id_prefix`: The prefix of the faucet account ID
    ///
    /// The origin token address and origin network are not supplied here: the bridge reads them
    /// back from its own faucet metadata when clearing the token registry, so the cleared key is
    /// always the one written at registration.
    ///
    /// # Parameters
    /// - `faucet_account_id`: The account ID of the faucet to deregister
    /// - `sender_account_id`: The account ID of the note creator (must be the bridge admin)
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
        // Create note storage with 2 felts: [faucet_id_suffix, faucet_id_prefix]
        let storage_values: Vec<Felt> =
            vec![faucet_account_id.suffix(), faucet_account_id.prefix().as_felt()];

        let note_storage = NoteStorage::new(storage_values)?;

        // Generate a serial number for the note
        let serial_num = rng.draw_word();

        let recipient = NoteRecipient::new(serial_num, Self::script(), note_storage);

        let attachment = NetworkAccountTarget::new(target_account_id, NoteExecutionHint::Always)
            .map_err(|e| NoteError::other(e.to_string()))?;
        let attachments = NoteAttachments::from(NoteAttachment::from(attachment));
        let metadata = PartialNoteMetadata::new(sender_account_id, NoteType::Public);

        // DEREGISTER_AGG_FAUCET notes don't carry assets
        let assets = NoteAssets::new(vec![])?;

        Ok(Note::with_attachments(assets, metadata, recipient, attachments))
    }
}
