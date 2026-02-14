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
use miden_standards::account::faucets::NetworkFungibleFaucet;
use miden_utils_sync::LazyLock;

pub mod b2agg_note;
pub mod claim_note;
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
pub use eth_types::{EthAddressFormat, EthAmount, EthAmountError};
pub use update_ger_note::UpdateGerNote;

// STORAGE SLOT NAMES
// ================================================================================================

static AGGLAYER_FAUCET_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet")
        .expect("agglayer faucet storage slot name should be valid")
});

static AGGLAYER_BRIDGE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge")
        .expect("agglayer bridge storage slot name should be valid")
});

// AGGLAYER FAUCET
// ================================================================================================

/// An [`AccountComponent`] implementing an AggLayer faucet.
///
/// This component combines network faucet functionality with bridge validation
/// via Foreign Procedure Invocation (FPI). It provides a "claim" procedure that
/// validates CLAIM notes against a bridge MMR account before minting assets.
///
/// ## Storage Layout
///
/// - [`NetworkFungibleFaucet::metadata_slot`]: Fungible faucet metadata (max_supply, decimals,
///   token_symbol).
/// - [`Self::bridge_slot`]: The bridge account ID for FPI validation.
pub struct AggLayerFaucet {
    token_symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    bridge_account_id: AccountId,
}

impl AggLayerFaucet {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AggLayerFaucet`] component from the given configuration.
    ///
    /// # Parameters
    /// - `token_symbol`: The symbol for the fungible token (e.g., "AGG")
    /// - `decimals`: Number of decimal places for the token
    /// - `max_supply`: Maximum supply of the token
    /// - `bridge_account_id`: The account ID of the bridge account for validation
    pub fn new(
        token_symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        bridge_account_id: AccountId,
    ) -> Self {
        Self {
            token_symbol,
            decimals,
            max_supply,
            bridge_account_id,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the bridge account ID is stored.
    pub fn bridge_slot() -> &'static StorageSlotName {
        &AGGLAYER_FAUCET_SLOT_NAME
    }

    /// Returns the token symbol of the faucet.
    pub fn token_symbol(&self) -> TokenSymbol {
        self.token_symbol
    }

    /// Returns the number of decimals for the token.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns the maximum supply of the token.
    pub fn max_supply(&self) -> Felt {
        self.max_supply
    }

    /// Returns the bridge account ID used for FPI validation.
    pub fn bridge_account_id(&self) -> AccountId {
        self.bridge_account_id
    }
}

impl From<AggLayerFaucet> for AccountComponent {
    fn from(faucet: AggLayerFaucet) -> Self {
        // Create network faucet metadata slot: [token_supply, max_supply, decimals, symbol]
        let metadata_word = Word::new([
            FieldElement::ZERO, // token_supply starts at 0
            faucet.max_supply,
            Felt::from(faucet.decimals),
            faucet.token_symbol.into(),
        ]);
        let metadata_slot =
            StorageSlot::with_value(NetworkFungibleFaucet::metadata_slot().clone(), metadata_word);

        // Create agglayer-specific bridge storage slot
        // Storage format: [0, 0, suffix, prefix]
        let bridge_account_id_word = Word::new([
            Felt::new(0),
            Felt::new(0),
            faucet.bridge_account_id.suffix(),
            faucet.bridge_account_id.prefix().as_felt(),
        ]);
        let bridge_slot =
            StorageSlot::with_value(AggLayerFaucet::bridge_slot().clone(), bridge_account_id_word);

        // Combine all storage slots for the agglayer faucet component
        let storage_slots = vec![metadata_slot, bridge_slot];

        let metadata = AccountComponentMetadata::new("agglayer::faucet")
            .with_description("AggLayer faucet component with bridge validation")
            .with_supports_all_types();

        AccountComponent::new(agglayer_faucet_library(), storage_slots, metadata)
            .expect("agglayer faucet component should satisfy the requirements of a valid account component")
    }
}

// AGGLAYER BRIDGE
// ================================================================================================

/// An [`AccountComponent`] implementing an AggLayer bridge.
///
/// This component provides bridge functionality for managing the MMR (Merkle Mountain Range)
/// that tracks bridged assets. It uses an empty map storage slot for the bridge state.
///
/// ## Storage Layout
///
/// - [`Self::bridge_slot`]: An empty map for bridge state management.
pub struct AggLayerBridge;

impl AggLayerBridge {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AggLayerBridge`] component.
    pub fn new() -> Self {
        Self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the bridge state map is stored.
    pub fn bridge_slot() -> &'static StorageSlotName {
        &AGGLAYER_BRIDGE_SLOT_NAME
    }
}

impl Default for AggLayerBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl From<AggLayerBridge> for AccountComponent {
    fn from(_bridge: AggLayerBridge) -> Self {
        let bridge_storage_slots =
            vec![StorageSlot::with_empty_map(AggLayerBridge::bridge_slot().clone())];

        let metadata = AccountComponentMetadata::new("agglayer::bridge")
            .with_description("AggLayer bridge component for MMR validation")
            .with_supports_all_types();

        AccountComponent::new(bridge_out_library(), bridge_storage_slots, metadata)
            .expect("bridge component should satisfy the requirements of a valid account component")
    }
}

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

// Initialize the unified AggLayer library only once
static AGGLAYER_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/agglayer.masl"));
    Library::read_from_bytes(bytes).expect("Shipped AggLayer library is well-formed")
});

/// Returns the unified AggLayer Library containing all agglayer modules.
pub fn agglayer_library() -> Library {
    AGGLAYER_LIBRARY.clone()
}

/// Returns the Bridge Out Library.
///
/// Note: This is now the same as agglayer_library() since all agglayer components
/// are compiled into a single library.
pub fn bridge_out_library() -> Library {
    agglayer_library()
}

/// Returns the Local Exit Tree Library.
///
/// Note: This is now the same as agglayer_library() since all agglayer components
/// are compiled into a single library.
pub fn local_exit_tree_library() -> Library {
    agglayer_library()
}

/// Creates a Local Exit Tree component with the specified storage slots.
///
/// This component uses the local_exit_tree library and can be added to accounts
/// that need to manage local exit tree functionality.
pub fn local_exit_tree_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = local_exit_tree_library();
    let metadata = AccountComponentMetadata::new("agglayer::local_exit_tree")
        .with_description("Local exit tree component for AggLayer")
        .with_supports_all_types();

    AccountComponent::new(library, storage_slots, metadata).expect(
        "local_exit_tree component should satisfy the requirements of a valid account component",
    )
}

/// Creates a Bridge Out component with the specified storage slots.
///
/// This component uses the bridge_out library and can be added to accounts
/// that need to bridge assets out to the AggLayer.
pub fn bridge_out_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = bridge_out_library();
    let metadata = AccountComponentMetadata::new("agglayer::bridge_out")
        .with_description("Bridge out component for AggLayer")
        .with_supports_all_types();

    AccountComponent::new(library, storage_slots, metadata)
        .expect("bridge_out component should satisfy the requirements of a valid account component")
}

/// Returns the Bridge In Library.
///
/// Note: This is now the same as agglayer_library() since all agglayer components
/// are compiled into a single library.
pub fn bridge_in_library() -> Library {
    agglayer_library()
}

/// Creates a Bridge In component with the specified storage slots.
///
/// This component uses the agglayer library and can be added to accounts
/// that need to bridge assets in from the AggLayer.
pub fn bridge_in_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = bridge_in_library();
    let metadata = AccountComponentMetadata::new("agglayer::bridge_in")
        .with_description("Bridge in component for AggLayer")
        .with_supports_all_types();

    AccountComponent::new(library, storage_slots, metadata)
        .expect("bridge_in component should satisfy the requirements of a valid account component")
}

/// Returns the Agglayer Faucet Library.
///
/// Note: This is now the same as agglayer_library() since all agglayer components
/// are compiled into a single library.
pub fn agglayer_faucet_library() -> Library {
    agglayer_library()
}

/// Creates an Agglayer Faucet component with the specified storage slots.
///
/// This component combines network faucet functionality with bridge validation
/// via Foreign Procedure Invocation (FPI). It provides a "claim" procedure that
/// validates CLAIM notes against a bridge MMR account before minting assets.
pub fn agglayer_faucet_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_faucet_library();
    let metadata = AccountComponentMetadata::new("agglayer::faucet")
        .with_description("AggLayer faucet component with bridge validation")
        .with_supported_type(AccountType::FungibleFaucet);

    AccountComponent::new(library, storage_slots, metadata).expect(
        "agglayer_faucet component should satisfy the requirements of a valid account component",
    )
}

/// Creates a combined Bridge Out component that includes both bridge_out and local_exit_tree
/// modules.
///
/// This is a convenience function that creates a component with multiple modules.
/// For more fine-grained control, use the individual component functions and combine them
/// using the AccountBuilder pattern.
pub fn bridge_out_with_local_exit_tree_component(
    storage_slots: Vec<StorageSlot>,
) -> Vec<AccountComponent> {
    vec![
        bridge_out_component(storage_slots.clone()),
        local_exit_tree_component(vec![]), // local_exit_tree typically doesn't need storage slots
    ]
}

/// Creates an Asset Conversion component with the specified storage slots.
///
/// This component uses the agglayer library (which includes asset_conversion) and can be added to
/// accounts that need to convert assets between Miden and Ethereum formats.
pub fn asset_conversion_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_library();
    let metadata = AccountComponentMetadata::new("agglayer::asset_conversion")
        .with_description("Asset conversion component for Miden/Ethereum formats")
        .with_supports_all_types();

    AccountComponent::new(library, storage_slots, metadata).expect(
        "asset_conversion component should satisfy the requirements of a valid account component",
    )
}

// AGGLAYER ACCOUNT CREATION HELPERS
// ================================================================================================

/// Creates a bridge account component with the standard bridge storage slot.
///
/// This is a convenience function that creates an [`AggLayerBridge`] and converts it
/// to an [`AccountComponent`].
///
/// # Returns
/// Returns an [`AccountComponent`] configured for bridge operations with MMR validation.
pub fn create_bridge_account_component() -> AccountComponent {
    AggLayerBridge::new().into()
}

/// Creates a complete bridge account builder with the standard configuration.
pub fn create_bridge_account_builder(seed: Word) -> AccountBuilder {
    // Create the "bridge_in" component
    let ger_upper_storage_slot_name = StorageSlotName::new("miden::agglayer::bridge::ger_upper")
        .expect("Bridge storage slot name should be valid");
    let ger_lower_storage_slot_name = StorageSlotName::new("miden::agglayer::bridge::ger_lower")
        .expect("Bridge storage slot name should be valid");
    let bridge_in_storage_slots = vec![
        StorageSlot::with_value(ger_upper_storage_slot_name, Word::empty()),
        StorageSlot::with_value(ger_lower_storage_slot_name, Word::empty()),
    ];

    let bridge_in_component = bridge_in_component(bridge_in_storage_slots);

    // Create the "bridge_out" component
    let let_storage_slot_name = StorageSlotName::new("miden::agglayer::let").unwrap();
    let bridge_out_storage_slots = vec![StorageSlot::with_empty_map(let_storage_slot_name)];
    let bridge_out_component = bridge_out_component(bridge_out_storage_slots);

    // Combine the components into a single account(builder)
    Account::builder(seed.into())
        .storage_mode(AccountStorageMode::Network)
        .with_component(bridge_out_component)
        .with_component(bridge_in_component)
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
///
/// # Panics
/// Panics if the token symbol is invalid.
pub fn create_agglayer_faucet_builder(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    bridge_account_id: AccountId,
) -> AccountBuilder {
    let token_symbol = TokenSymbol::new(token_symbol).expect("Token symbol should be valid");
    let agglayer_component: AccountComponent =
        AggLayerFaucet::new(token_symbol, decimals, max_supply, bridge_account_id).into();

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
) -> Account {
    create_agglayer_faucet_builder(seed, token_symbol, decimals, max_supply, bridge_account_id)
        .with_auth_component(AccountComponent::from(NoAuth))
        .build()
        .expect("Agglayer faucet account should be valid")
}

/// Creates an existing agglayer faucet account with the specified configuration.
///
/// This creates an existing account suitable for testing scenarios.
#[cfg(any(feature = "testing", test))]
pub fn create_existing_agglayer_faucet(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    bridge_account_id: AccountId,
) -> Account {
    create_agglayer_faucet_builder(seed, token_symbol, decimals, max_supply, bridge_account_id)
        .with_auth_component(AccountComponent::from(NoAuth))
        .build_existing()
        .expect("Agglayer faucet account should be valid")
}
