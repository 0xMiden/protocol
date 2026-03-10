extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, FieldElement, Word};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
use miden_standards::account::faucets::{FungibleFaucetError, TokenMetadata};
use miden_utils_sync::LazyLock;

use super::agglayer_faucet_component_library;
pub use crate::{
    AggLayerBridge,
    B2AggNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    EthAddressFormat,
    EthAmount,
    EthAmountError,
    ExitRoot,
    GlobalIndex,
    GlobalIndexError,
    LeafData,
    MetadataHash,
    ProofData,
    SmtNode,
    UpdateGerNote,
    create_claim_note,
};

/// Creates an Agglayer Faucet component with the specified storage slots.
///
/// This component combines network faucet functionality with bridge validation
/// via Foreign Procedure Invocation (FPI). It provides a "claim" procedure that
/// validates CLAIM notes against a bridge MMR account before minting assets.
fn agglayer_faucet_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_faucet_component_library();
    let metadata = AccountComponentMetadata::new("agglayer::faucet")
        .with_description("AggLayer faucet component with bridge validation")
        .with_supported_type(AccountType::FungibleFaucet);

    AccountComponent::new(library, storage_slots, metadata).expect(
        "agglayer_faucet component should satisfy the requirements of a valid account component",
    )
}

// FAUCET CONVERSION STORAGE HELPERS
// ================================================================================================

/// Builds the two storage slot values for faucet conversion metadata.
///
/// The conversion metadata is stored in two value storage slots:
/// - Slot 1 (`miden::agglayer::faucet::conversion_info_1`): `[addr0, addr1, addr2, addr3]` — first
///   4 felts of the origin token address (5 × u32 limbs).
/// - Slot 2 (`miden::agglayer::faucet::conversion_info_2`): `[addr4, origin_network, scale, 0]` —
///   remaining address felt + origin network + scale factor.
///
/// # Parameters
/// - `origin_token_address`: The EVM token address in Ethereum format
/// - `origin_network`: The origin network/chain ID
/// - `scale`: The decimal scaling factor (exponent for 10^scale)
///
/// # Returns
/// A tuple of two `Word` values representing the two storage slot contents.
fn agglayer_faucet_conversion_slots(
    origin_token_address: &EthAddressFormat,
    origin_network: u32,
    scale: u8,
) -> (Word, Word) {
    let addr_elements = origin_token_address.to_elements();

    let slot1 = Word::new([addr_elements[0], addr_elements[1], addr_elements[2], addr_elements[3]]);

    let slot2 =
        Word::new([addr_elements[4], Felt::from(origin_network), Felt::from(scale), Felt::ZERO]);

    (slot1, slot2)
}

// AGGLAYER FAUCET STRUCT
// ================================================================================================

static AGGLAYER_FAUCET_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet")
        .expect("agglayer faucet storage slot name should be valid")
});
static CONVERSION_INFO_1_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet::conversion_info_1")
        .expect("conversion info 1 storage slot name should be valid")
});
static CONVERSION_INFO_2_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet::conversion_info_2")
        .expect("conversion info 2 storage slot name should be valid")
});

/// An [`AccountComponent`] implementing the AggLayer Faucet.
///
/// It reexports the procedures from `miden::agglayer::faucet`. When linking against this
/// component, the `agglayer` library must be available to the assembler.
/// The procedures of this component are:
/// - `claim`, which validates a CLAIM note against one of the stored GERs in the bridge.
/// - `asset_to_origin_asset`, which converts an asset to the origin asset (used in FPI from
///   bridge).
/// - `burn`, which burns an asset.
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Stores [`TokenMetadata`].
/// - [`Self::bridge_account_id_slot`]: Stores the AggLayer bridge account ID.
/// - [`Self::conversion_info_1_slot`]: Stores the first 4 felts of the origin token address.
/// - [`Self::conversion_info_2_slot`]: Stores the remaining 5th felt of the origin token address +
///   origin network + scale.
#[derive(Debug, Clone)]
pub struct AggLayerFaucet {
    metadata: TokenMetadata,
    bridge_account_id: AccountId,
    origin_token_address: EthAddressFormat,
    origin_network: u32,
    scale: u8,
}

impl AggLayerFaucet {
    /// Creates a new AggLayer faucet component from the given configuration.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The decimals parameter exceeds maximum value of [`TokenMetadata::MAX_DECIMALS`].
    /// - The max supply exceeds maximum possible amount for a fungible asset.
    /// - The token supply exceeds the max supply.
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        token_supply: Felt,
        bridge_account_id: AccountId,
        origin_token_address: EthAddressFormat,
        origin_network: u32,
        scale: u8,
    ) -> Result<Self, FungibleFaucetError> {
        let metadata = TokenMetadata::with_supply(symbol, decimals, max_supply, token_supply)?;
        Ok(Self {
            metadata,
            bridge_account_id,
            origin_token_address,
            origin_network,
            scale,
        })
    }

    /// Sets the token supply for an existing faucet (e.g. for testing scenarios).
    ///
    /// # Errors
    /// Returns an error if the token supply exceeds the max supply.
    pub fn with_token_supply(mut self, token_supply: Felt) -> Result<Self, FungibleFaucetError> {
        self.metadata = self.metadata.with_token_supply(token_supply)?;
        Ok(self)
    }

    /// Storage slot name for [`TokenMetadata`].
    pub fn metadata_slot() -> &'static StorageSlotName {
        TokenMetadata::metadata_slot()
    }

    /// Storage slot name for the AggLayer bridge account ID.
    pub fn bridge_account_id_slot() -> &'static StorageSlotName {
        &AGGLAYER_FAUCET_SLOT_NAME
    }

    /// Storage slot name for the first 4 felts of the origin token address.
    pub fn conversion_info_1_slot() -> &'static StorageSlotName {
        &CONVERSION_INFO_1_SLOT_NAME
    }

    /// Storage slot name for the 5th felt of the origin token address, origin network, and scale.
    pub fn conversion_info_2_slot() -> &'static StorageSlotName {
        &CONVERSION_INFO_2_SLOT_NAME
    }
}

impl From<AggLayerFaucet> for AccountComponent {
    fn from(faucet: AggLayerFaucet) -> Self {
        let metadata_slot = StorageSlot::from(faucet.metadata);

        let bridge_account_id_word = Word::new([
            Felt::ZERO,
            Felt::ZERO,
            faucet.bridge_account_id.suffix(),
            faucet.bridge_account_id.prefix().as_felt(),
        ]);
        let bridge_slot =
            StorageSlot::with_value(AGGLAYER_FAUCET_SLOT_NAME.clone(), bridge_account_id_word);

        let (conversion_slot1_word, conversion_slot2_word) = agglayer_faucet_conversion_slots(
            &faucet.origin_token_address,
            faucet.origin_network,
            faucet.scale,
        );
        let conversion_slot1 =
            StorageSlot::with_value(CONVERSION_INFO_1_SLOT_NAME.clone(), conversion_slot1_word);
        let conversion_slot2 =
            StorageSlot::with_value(CONVERSION_INFO_2_SLOT_NAME.clone(), conversion_slot2_word);

        let agglayer_storage_slots =
            vec![metadata_slot, bridge_slot, conversion_slot1, conversion_slot2];
        agglayer_faucet_component(agglayer_storage_slots)
    }
}

// FAUCET REGISTRY HELPERS
// ================================================================================================

/// Creates a faucet registry map key from a faucet account ID.
///
/// The key format is `[0, 0, faucet_id_suffix, faucet_id_prefix]`.
pub fn faucet_registry_key(faucet_id: AccountId) -> Word {
    Word::new([Felt::ZERO, Felt::ZERO, faucet_id.suffix(), faucet_id.prefix().as_felt()])
}
