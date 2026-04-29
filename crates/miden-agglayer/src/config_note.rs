//! CONFIG_AGG_BRIDGE note creation utilities.
//!
//! This module provides helpers for creating CONFIG_AGG_BRIDGE notes,
//! which are used to register faucets in the bridge's faucet registry.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use miden_assembly::Library;
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
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_utils_sync::LazyLock;

use crate::EthAddress;

// NOTE SCRIPT
// ================================================================================================

// Initialize the CONFIG_AGG_BRIDGE note script only once
static CONFIG_AGG_BRIDGE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/config_agg_bridge.masl"));
    let library = Library::read_from_bytes(bytes)
        .expect("shipped CONFIG_AGG_BRIDGE script library is well-formed");
    NoteScript::from_library(&library).expect("shipped CONFIG_AGG_BRIDGE script is well-formed")
});

// CONFIG_AGG_BRIDGE NOTE
// ================================================================================================

/// CONFIG_AGG_BRIDGE note.
///
/// This note is used to register a faucet in the bridge's faucet and token registries.
/// It carries the origin token address and faucet account ID, and is always public.
pub struct ConfigAggBridgeNote;

impl ConfigAggBridgeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a CONFIG_AGG_BRIDGE note.
    /// Layout: [origin_token_addr(5), faucet_id_suffix, faucet_id_prefix]
    pub const NUM_STORAGE_ITEMS: usize = 7;

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
    /// The note storage contains 7 felts:
    /// - `origin_token_addr[0..5]`: The 5 u32 felts of the origin EVM token address
    /// - `faucet_id_suffix`: The suffix of the faucet account ID
    /// - `faucet_id_prefix`: The prefix of the faucet account ID
    ///
    /// # Parameters
    /// - `faucet_account_id`: The account ID of the faucet to register
    /// - `origin_token_address`: The origin EVM token address for the token registry
    /// - `sender_account_id`: The account ID of the note creator
    /// - `target_account_id`: The bridge account ID that will consume this note
    /// - `rng`: Random number generator for creating the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        faucet_account_id: AccountId,
        origin_token_address: &EthAddress,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        // Create note storage with 7 felts: [origin_token_addr(5), faucet_id_suffix,
        // faucet_id_prefix]
        let addr_elements = origin_token_address.to_elements();
        let mut storage_values: Vec<Felt> = addr_elements;
        storage_values.push(faucet_account_id.suffix());
        storage_values.push(faucet_account_id.prefix().as_felt());

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
