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
/// This is a convenience function that creates the bridge storage slot with the standard
/// name "miden::agglayer::bridge" and returns the bridge_out component.
///
/// # Returns
/// Returns an [`AccountComponent`] configured for bridge operations with MMR validation.
pub fn create_bridge_account_component() -> AccountComponent {
    let bridge_storage_slot_name = StorageSlotName::new("miden::agglayer::bridge")
        .expect("Bridge storage slot name should be valid");
    let bridge_storage_slots = vec![StorageSlot::with_empty_map(bridge_storage_slot_name)];
    bridge_out_component(bridge_storage_slots)
}

/// Creates an agglayer faucet account component with the specified configuration.
///
/// This function creates all the necessary storage slots for an agglayer faucet:
/// - Network faucet metadata slot (max_supply, decimals, token_symbol)
/// - Bridge account reference slot for FPI validation
///
/// # Parameters
/// - `token_symbol`: The symbol for the fungible token (e.g., "AGG")
/// - `decimals`: Number of decimal places for the token
/// - `max_supply`: Maximum supply of the token
/// - `bridge_account_id`: The account ID of the bridge account for validation
///
/// # Returns
/// Returns an [`AccountComponent`] configured for agglayer faucet operations.
///
/// # Panics
/// Panics if the token symbol is invalid or storage slot names are malformed.
pub fn create_agglayer_faucet_component(
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    bridge_account_id: AccountId,
) -> AccountComponent {
    // Create network faucet metadata slot: [0, max_supply, decimals, token_symbol]
    let token_symbol = TokenSymbol::new(token_symbol).expect("Token symbol should be valid");
    let metadata_word =
        Word::new([FieldElement::ZERO, max_supply, Felt::from(decimals), token_symbol.into()]);
    let metadata_slot =
        StorageSlot::with_value(NetworkFungibleFaucet::metadata_slot().clone(), metadata_word);

    // Create agglayer-specific bridge storage slot
    let bridge_account_id_word = Word::new([
        Felt::new(0),
        Felt::new(0),
        bridge_account_id.suffix(),
        bridge_account_id.prefix().as_felt(),
    ]);
    let agglayer_storage_slot_name = StorageSlotName::new("miden::agglayer::faucet")
        .expect("Agglayer faucet storage slot name should be valid");
    let bridge_slot = StorageSlot::with_value(agglayer_storage_slot_name, bridge_account_id_word);

    // Combine all storage slots for the agglayer faucet component
    let agglayer_storage_slots = vec![metadata_slot, bridge_slot];
    agglayer_faucet_component(agglayer_storage_slots)
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
pub fn create_agglayer_faucet_builder(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    bridge_account_id: AccountId,
) -> AccountBuilder {
    let agglayer_component =
        create_agglayer_faucet_component(token_symbol, decimals, max_supply, bridge_account_id);

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
