#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use miden_assembly::Library;
use miden_assembly::utils::Deserializable;
use miden_core::{Felt, FieldElement, Program, Word};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorageMode,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
use miden_protocol::note::NoteScript;
use miden_standards::account::auth::NoAuth;
use miden_standards::account::faucets::{FungibleFaucetError, TokenMetadata};
use miden_utils_sync::LazyLock;

pub mod b2agg_note;
pub mod claim_note;
pub mod config_note;
pub mod errors;
pub mod eth_types;
pub mod update_ger_note;
pub mod utils;

pub use b2agg_note::B2AggNote;
pub use claim_note::{
    ClaimNoteStorage,
    ExitRoot,
    LeafData,
    OutputNoteData,
    ProofData,
    SmtNode,
    create_claim_note,
};
pub use config_note::ConfigAggBridgeNote;
pub use eth_types::{
    EthAddressFormat,
    EthAmount,
    EthAmountError,
    GlobalIndex,
    GlobalIndexError,
    MetadataHash,
};
pub use update_ger_note::UpdateGerNote;

// AGGLAYER NOTE SCRIPTS
// ================================================================================================

// Initialize the CLAIM note script only once
static CLAIM_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/CLAIM.masb"));
    let program = Program::read_from_bytes(bytes).expect("Shipped CLAIM script is well-formed");
    NoteScript::new(program)
});

/// Returns the CLAIM (Bridge from AggLayer) note script.
pub fn claim_script() -> NoteScript {
    CLAIM_SCRIPT.clone()
}

// AGGLAYER ACCOUNT COMPONENTS
// ================================================================================================

static AGGLAYER_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/agglayer.masl"));
    Library::read_from_bytes(bytes).expect("Shipped AggLayer library is well-formed")
});

static BRIDGE_COMPONENT_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/bridge.masl"));
    Library::read_from_bytes(bytes).expect("Shipped bridge component library is well-formed")
});

static FAUCET_COMPONENT_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/faucet.masl"));
    Library::read_from_bytes(bytes).expect("Shipped faucet component library is well-formed")
});

/// Returns the unified AggLayer Library containing all agglayer modules.
///
/// This library contains all procedures from both the bridge and faucet modules.
/// For component-specific libraries that only expose relevant procedures, use
/// [`agglayer_bridge_library()`] or [`agglayer_faucet_library()`] instead.
pub fn agglayer_library() -> Library {
    AGGLAYER_LIBRARY.clone()
}

/// Returns the Bridge component library.
///
/// This library only exposes bridge-related procedures (bridge_out, bridge_in,
/// bridge_config, local_exit_tree).
fn agglayer_bridge_library() -> Library {
    BRIDGE_COMPONENT_LIBRARY.clone()
}

/// Returns the Faucet component library.
///
/// This library only exposes faucet-related procedures (claim, get_origin_token_address,
/// etc.).
fn agglayer_faucet_library() -> Library {
    FAUCET_COMPONENT_LIBRARY.clone()
}

/// Creates a Bridge component with the specified storage slots.
///
/// This component uses the bridge library and can be added to accounts
/// that need bridge functionality (bridge_out, bridge_in, bridge_config,
/// local_exit_tree).
fn bridge_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_bridge_library();
    let metadata = AccountComponentMetadata::new("agglayer::bridge")
        .with_description("Bridge component for AggLayer")
        .with_supports_all_types();

    AccountComponent::new(library, storage_slots, metadata)
        .expect("bridge component should satisfy the requirements of a valid account component")
}

// AGGLAYER BRIDGE STRUCT
// ================================================================================================

static GER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::ger").expect("Bridge storage slot name should be valid")
});
static LET_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let").expect("LET storage slot name should be valid")
});
static LET_ROOT_LO_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let::root_lo").expect("LET root_lo storage slot name should be valid")
});
static LET_ROOT_HI_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let::root_hi").expect("LET root_hi storage slot name should be valid")
});
static LET_NUM_LEAVES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let::num_leaves").expect("LET num_leaves storage slot name should be valid")
});
static FAUCET_REGISTRY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::faucet_registry")
        .expect("Faucet registry storage slot name should be valid")
});

/// AggLayer Bridge component for accounts that need bridge functionality.
///
/// This component provides bridge_out, bridge_in, bridge_config, and local_exit_tree
/// procedures. The bridge starts with an empty faucet registry; faucets are registered
/// at runtime via CONFIG_AGG_BRIDGE notes.
#[derive(Debug, Clone, Copy, Default)]
pub struct AggLayerBridge;

impl AggLayerBridge {
    /// Creates a new AggLayer bridge component with the standard configuration.
    pub fn new() -> Self {
        Self
    }
}

impl From<AggLayerBridge> for AccountComponent {
    fn from(_: AggLayerBridge) -> Self {
        let bridge_storage_slots = vec![
            StorageSlot::with_empty_map(GER_SLOT_NAME.clone()),
            StorageSlot::with_empty_map(LET_SLOT_NAME.clone()),
            StorageSlot::with_value(LET_ROOT_LO_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(LET_ROOT_HI_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(LET_NUM_LEAVES_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_empty_map(FAUCET_REGISTRY_SLOT_NAME.clone()),
        ];
        bridge_component(bridge_storage_slots)
    }
}

/// Creates an Agglayer Faucet component with the specified storage slots.
///
/// This component combines network faucet functionality with bridge validation
/// via Foreign Procedure Invocation (FPI). It provides a "claim" procedure that
/// validates CLAIM notes against a bridge MMR account before minting assets.
fn agglayer_faucet_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_faucet_library();
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
        .expect("Agglayer faucet storage slot name should be valid")
});
static CONVERSION_INFO_1_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet::conversion_info_1")
        .expect("Conversion info 1 storage slot name should be valid")
});
static CONVERSION_INFO_2_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet::conversion_info_2")
        .expect("Conversion info 2 storage slot name should be valid")
});

/// AggLayer faucet component with bridge validation.
///
/// This component combines network faucet functionality with bridge validation
/// via Foreign Procedure Invocation (FPI). It provides a "claim" procedure that
/// validates CLAIM notes against a bridge MMR account before minting assets.
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
/// The key format is `[faucet_id_prefix, faucet_id_suffix, 0, 0]`.
pub fn faucet_registry_key(faucet_id: AccountId) -> Word {
    Word::new([Felt::ZERO, Felt::ZERO, faucet_id.suffix(), faucet_id.prefix().as_felt()])
}

// AGGLAYER ACCOUNT CREATION HELPERS
// ================================================================================================

/// Creates an agglayer faucet account component with the specified configuration.
///
/// This function creates all the necessary storage slots for an agglayer faucet:
/// - Network faucet metadata slot (token_supply, max_supply, decimals, token_symbol)
/// - Bridge account reference slot for FPI validation
/// - Conversion info slot 1: first 4 felts of origin token address
/// - Conversion info slot 2: 5th address felt + origin network + scale
///
/// # Parameters
/// - `token_symbol`: The symbol for the fungible token (e.g., "AGG")
/// - `decimals`: Number of decimal places for the token
/// - `max_supply`: Maximum supply of the token
/// - `token_supply`: Initial outstanding token supply (0 for new faucets)
/// - `bridge_account_id`: The account ID of the bridge account for validation
/// - `origin_token_address`: The EVM origin token address
/// - `origin_network`: The origin network/chain ID
/// - `scale`: The decimal scaling factor (exponent for 10^scale)
///
/// # Returns
/// Returns an [`AccountComponent`] configured for agglayer faucet operations.
///
/// # Panics
/// Panics if the token symbol is invalid or metadata validation fails.
fn create_agglayer_faucet_component(
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
    origin_token_address: &EthAddressFormat,
    origin_network: u32,
    scale: u8,
) -> AccountComponent {
    let symbol = TokenSymbol::new(token_symbol).expect("Token symbol should be valid");
    AggLayerFaucet::new(
        symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_account_id,
        *origin_token_address,
        origin_network,
        scale,
    )
    .expect("AggLayer faucet metadata should be valid")
    .into()
}

/// Creates a complete bridge account builder with the standard configuration.
///
/// The bridge starts with an empty faucet registry. Faucets are registered at runtime
/// via CONFIG_AGG_BRIDGE notes that call `bridge_config::register_faucet`.
fn create_bridge_account_builder(seed: Word) -> AccountBuilder {
    Account::builder(seed.into())
        .storage_mode(AccountStorageMode::Network)
        .with_component(AggLayerBridge::new())
}

/// Creates a new bridge account with the standard configuration.
///
/// This creates a new account suitable for production use.
pub fn create_bridge_account(seed: Word) -> Account {
    create_bridge_account_builder(seed)
        .with_auth_component(AccountComponent::from(NoAuth))
        .build()
        .expect("Bridge account should be valid")
}

/// Creates an existing bridge account with the standard configuration.
///
/// This creates an existing account suitable for testing scenarios.
#[cfg(any(feature = "testing", test))]
pub fn create_existing_bridge_account(seed: Word) -> Account {
    create_bridge_account_builder(seed)
        .with_auth_component(AccountComponent::from(NoAuth))
        .build_existing()
        .expect("Bridge account should be valid")
}

/// Creates a complete agglayer faucet account builder with the specified configuration.
#[allow(clippy::too_many_arguments)]
fn create_agglayer_faucet_builder(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
    origin_token_address: &EthAddressFormat,
    origin_network: u32,
    scale: u8,
) -> AccountBuilder {
    let agglayer_component = create_agglayer_faucet_component(
        token_symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_account_id,
        origin_token_address,
        origin_network,
        scale,
    );

    Account::builder(seed.into())
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_component(agglayer_component)
}

/// Creates a new agglayer faucet account with the specified configuration.
///
/// This creates a new account suitable for production use.
pub fn create_agglayer_faucet(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    bridge_account_id: AccountId,
    origin_token_address: &EthAddressFormat,
    origin_network: u32,
    scale: u8,
) -> Account {
    create_agglayer_faucet_builder(
        seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account_id,
        origin_token_address,
        origin_network,
        scale,
    )
    .with_auth_component(AccountComponent::from(NoAuth))
    .build()
    .expect("Agglayer faucet account should be valid")
}

/// Creates an existing agglayer faucet account with the specified configuration.
///
/// This creates an existing account suitable for testing scenarios.
#[cfg(any(feature = "testing", test))]
#[allow(clippy::too_many_arguments)]
pub fn create_existing_agglayer_faucet(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
    origin_token_address: &EthAddressFormat,
    origin_network: u32,
    scale: u8,
) -> Account {
    create_agglayer_faucet_builder(
        seed,
        token_symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_account_id,
        origin_token_address,
        origin_network,
        scale,
    )
    .with_auth_component(AccountComponent::from(NoAuth))
    .build_existing()
    .expect("Agglayer faucet account should be valid")
}
