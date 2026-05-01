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

// CONVERSION METADATA
// ================================================================================================

/// The conversion metadata registered on the bridge for a single faucet.
///
/// Encapsulates the origin-chain identity and bridge-side policy of a faucet: the EVM token
/// address, network id, decimal scale, whether the faucet is Miden-native (lock/unlock) or
/// bridge-owned (burn/mint), and the keccak256 metadata hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionMetadata {
    /// Account ID of the faucet being registered.
    pub faucet_account_id: AccountId,
    /// Origin EVM token address the faucet wraps.
    pub origin_token_address: EthAddress,
    /// Decimal scaling factor between the origin-chain unit and the Miden-side unit
    /// (e.g. 0 for USDC, 8 for ETH).
    pub scale: u8,
    /// Origin network / chain ID the token lives on.
    pub origin_network: u32,
    /// `true` for Miden-native faucets (bridge-in unlocks from the bridge vault, bridge-out
    /// locks into it); `false` for bridge-owned faucets (bridge-in mints via the faucet,
    /// bridge-out burns via the faucet).
    pub is_native: bool,
    /// keccak256 hash of the ABI-encoded token metadata (`name`, `symbol`, `decimals`).
    pub metadata_hash: MetadataHash,
}

impl ConversionMetadata {
    /// Serializes the metadata to the 18-felt layout consumed by `CONFIG_AGG_BRIDGE`.
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut v = Vec::with_capacity(ConfigAggBridgeNote::NUM_STORAGE_ITEMS);
        v.extend(self.origin_token_address.to_elements());
        v.push(self.faucet_account_id.suffix());
        v.push(self.faucet_account_id.prefix().as_felt());
        v.push(Felt::from(self.scale));
        v.push(Felt::from(self.origin_network));
        v.push(Felt::from(u8::from(self.is_native)));
        v.extend(self.metadata_hash.to_elements());
        v
    }
}

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
    /// # Parameters
    /// - `metadata`: The conversion metadata to register for the faucet.
    /// - `sender_account_id`: The account ID of the note creator.
    /// - `target_account_id`: The bridge account ID that will consume this note.
    /// - `rng`: Random number generator for creating the note serial number.
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        metadata: ConversionMetadata,
        sender_account_id: AccountId,
        target_account_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let storage_values = metadata.to_elements();

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
        let note_metadata =
            NoteMetadata::new(sender_account_id, NoteType::Public).with_attachment(attachment);

        // CONFIG_AGG_BRIDGE notes don't carry assets
        let assets = NoteAssets::new(vec![])?;

        Ok(Note::new(assets, note_metadata, recipient))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    use super::*;

    /// Locks in the 18-felt wire layout of `CONFIG_AGG_BRIDGE` note storage. Any reordering in
    /// `to_elements` would silently desync from the indices the MASM `CONFIG_AGG_BRIDGE` script
    /// reads from (`ORIGIN_TOKEN_ADDR_0..4`, `FAUCET_ID_SUFFIX=5`, ... `METADATA_HASH_HI_3=17`).
    #[test]
    fn to_elements_layout_matches_masm_storage_indices() {
        let faucet = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("valid faucet account id");
        let origin_token_address =
            EthAddress::from_hex("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let metadata_hash = MetadataHash::from_token_info("USD Coin", "USDC", 6);

        let metadata = ConversionMetadata {
            faucet_account_id: faucet,
            origin_token_address,
            scale: 6,
            origin_network: 42,
            is_native: true,
            metadata_hash,
        };

        let elements = metadata.to_elements();

        assert_eq!(elements.len(), ConfigAggBridgeNote::NUM_STORAGE_ITEMS);
        assert_eq!(&elements[0..5], origin_token_address.to_elements().as_slice());
        assert_eq!(elements[5], faucet.suffix());
        assert_eq!(elements[6], faucet.prefix().as_felt());
        assert_eq!(elements[7], Felt::from(6_u8));
        assert_eq!(elements[8], Felt::from(42_u32));
        assert_eq!(elements[9], Felt::from(1_u8));
        assert_eq!(&elements[10..18], metadata_hash.to_elements().as_slice());
    }
}
