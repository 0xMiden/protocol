//! CONFIG_AGG_BRIDGE note creation utilities.
//!
//! This module provides helpers for creating CONFIG_AGG_BRIDGE notes,
//! which are used to register faucets in the bridge's faucet registry.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

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

use crate::{EthAddress, MetadataHash};

// NOTE SCRIPT
// ================================================================================================

// Initialize the CONFIG_AGG_BRIDGE note script only once
static CONFIG_AGG_BRIDGE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/CONFIG_AGG_BRIDGE.masb"));
    let program =
        Program::read_from_bytes(bytes).expect("shipped CONFIG_AGG_BRIDGE script is well-formed");
    NoteScript::new(program)
});

// CONFIG_AGG_BRIDGE NOTE
// ================================================================================================

/// CONFIG_AGG_BRIDGE note.
///
/// This note is used to register a faucet in the bridge's faucet and token registries,
/// and to store full conversion metadata (origin address, origin network, scale, metadata hash)
/// in the bridge's faucet metadata map.
pub struct ConfigAggBridgeNote;

impl ConfigAggBridgeNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for a CONFIG_AGG_BRIDGE note.
    ///
    /// Layout (18 felts):
    /// - `[0..4]`   origin_token_addr (5 felts)
    /// - `[5]`      faucet_id_suffix
    /// - `[6]`      faucet_id_prefix
    /// - `[7]`      scale
    /// - `[8]`      origin_network
    /// - `[9]`      is_native (0 or 1)
    /// - `[10..13]` METADATA_HASH_LO (4 felts)
    /// - `[14..17]` METADATA_HASH_HI (4 felts)
    pub const NUM_STORAGE_ITEMS: usize = 18;

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
    /// The note storage contains 18 felts carrying all the data needed for faucet registration:
    /// - Origin token address (5 felts)
    /// - Faucet account ID (2 felts)
    /// - Scale factor (1 felt)
    /// - Origin network (1 felt)
    /// - Is-native flag (1 felt)
    /// - Metadata hash (8 felts)
    ///
    /// # Parameters
    /// - `faucet_account_id`: The account ID of the faucet to register
    /// - `origin_token_address`: The origin EVM token address for the token registry
    /// - `scale`: The decimal scaling factor (e.g. 0 for USDC, 8 for ETH)
    /// - `origin_network`: The origin network/chain ID
    /// - `is_native`: Whether this is a Miden-native faucet (lock/unlock) vs bridge-owned
    ///   (burn/mint)
    /// - `metadata_hash`: The keccak256 hash of ABI-encoded token metadata
    /// - `sender_account_id`: The account ID of the note creator
    /// - `target_account_id`: The bridge account ID that will consume this note
    /// - `rng`: Random number generator for creating the note serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create<R: FeltRng>(
        faucet_account_id: AccountId,
        origin_token_address: &EthAddress,
        scale: u8,
        origin_network: u32,
        is_native: bool,
        metadata_hash: &MetadataHash,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        // Create note storage with 18 felts
        let addr_elements = origin_token_address.to_elements();
        let mut storage_values: Vec<Felt> = addr_elements;
        storage_values.push(faucet_account_id.suffix());
        storage_values.push(faucet_account_id.prefix().as_felt());
        storage_values.push(Felt::from(scale));
        storage_values.push(Felt::from(origin_network));
        storage_values.push(Felt::from(u8::from(is_native)));
        storage_values.extend(metadata_hash.to_elements());

        debug_assert_eq!(
            storage_values.len(),
            Self::NUM_STORAGE_ITEMS,
            "CONFIG_AGG_BRIDGE storage must have exactly {} felts",
            Self::NUM_STORAGE_ITEMS
        );

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
