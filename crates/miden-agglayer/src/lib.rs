#![no_std]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use miden_assembly::Library;
use miden_assembly::utils::Deserializable;
use miden_core::{Felt, FieldElement, Program, Word};
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
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteExecutionHint,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_standards::account::auth::NoAuth;
use miden_standards::account::faucets::NetworkFungibleFaucet;
use miden_standards::note::NetworkAccountTarget;
use miden_utils_sync::LazyLock;

pub mod errors;
pub mod eth_address;
pub mod utils;

pub use eth_address::EthAddressFormat;
use utils::bytes32_to_felts;

// AGGLAYER NOTE SCRIPTS
// ================================================================================================

// Initialize the B2AGG note script only once
static B2AGG_SCRIPT: LazyLock<Program> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/B2AGG.masb"));
    Program::read_from_bytes(bytes).expect("Shipped B2AGG script is well-formed")
});

/// Returns the B2AGG (Bridge to AggLayer) note script.
pub fn b2agg_script() -> Program {
    B2AGG_SCRIPT.clone()
}

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

    AccountComponent::new(library, storage_slots)
        .expect("local_exit_tree component should satisfy the requirements of a valid account component")
        .with_supports_all_types()
}

/// Creates a Bridge Out component with the specified storage slots.
///
/// This component uses the bridge_out library and can be added to accounts
/// that need to bridge assets out to the AggLayer.
pub fn bridge_out_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = bridge_out_library();

    AccountComponent::new(library, storage_slots)
        .expect("bridge_out component should satisfy the requirements of a valid account component")
        .with_supports_all_types()
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

    AccountComponent::new(library, storage_slots)
        .expect("bridge_in component should satisfy the requirements of a valid account component")
        .with_supports_all_types()
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

    AccountComponent::new(library, storage_slots)
        .expect("agglayer_faucet component should satisfy the requirements of a valid account component")
        .with_supports_all_types()
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

    AccountComponent::new(library, storage_slots)
        .expect("asset_conversion component should satisfy the requirements of a valid account component")
        .with_supports_all_types()
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
    let bridge_component = create_bridge_account_component();
    Account::builder(seed.into())
        .storage_mode(AccountStorageMode::Public)
        .with_component(bridge_component)
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

// AGGLAYER NOTE CREATION HELPERS
// ================================================================================================

/// Parameters for creating a CLAIM note.
///
/// This struct groups all the parameters needed to create a CLAIM note that exactly
/// matches the agglayer claimAsset function signature.
pub struct ClaimNoteParams<'a, R: FeltRng> {
    /// AGGLAYER claimAsset function parameters
    /// SMT proof for local exit root (bytes32\[_DEPOSIT_CONTRACT_TREE_DEPTH\])
    pub smt_proof_local_exit_root: Vec<Felt>,
    /// SMT proof for rollup exit root (bytes32\[_DEPOSIT_CONTRACT_TREE_DEPTH\])
    pub smt_proof_rollup_exit_root: Vec<Felt>,
    /// Global index (uint256 as 8 u32 felts)
    pub global_index: [Felt; 8],
    /// Mainnet exit root hash (bytes32 as 32-byte array)
    pub mainnet_exit_root: &'a [u8; 32],
    /// Rollup exit root hash (bytes32 as 32-byte array)
    pub rollup_exit_root: &'a [u8; 32],
    /// Origin network identifier (uint32)
    pub origin_network: Felt,
    /// Origin token address (address as 20-byte array)
    pub origin_token_address: &'a [u8; 20],
    /// Destination network identifier (uint32)
    pub destination_network: Felt,
    /// Destination address (address as 20-byte array)
    pub destination_address: &'a [u8; 20],
    /// Amount of tokens (uint256 as 8 u32 felts)
    pub amount: [Felt; 8],
    /// ABI encoded metadata (fixed size of 8 felts)
    pub metadata: [Felt; 8],
    /// CLAIM note required parameters
    /// CLAIM note sender account id
    pub claim_note_creator_account_id: AccountId,
    /// Agglayer faucet AccountId
    pub agglayer_faucet_account_id: AccountId,
    /// Output P2ID note tag
    pub output_note_tag: NoteTag,
    /// P2ID note serial number (4 felts as Word)
    pub p2id_serial_number: Word,
    /// TODO: remove and use destination_address: [u8; 20]
    pub destination_account_id: AccountId,
    /// RNG for creating CLAIM note serial number
    pub rng: &'a mut R,
}

/// Generates a CLAIM note - a note that instructs an agglayer faucet to validate and mint assets.
///
/// # Parameters
/// - `params`: The parameters for creating the CLAIM note (including RNG)
///
/// # Errors
/// Returns an error if note creation fails.
pub fn create_claim_note<R: FeltRng>(params: ClaimNoteParams<'_, R>) -> Result<Note, NoteError> {
    // Validate SMT proof lengths - each should be 256 felts (32 bytes32 values * 8 u32 per bytes32)
    if params.smt_proof_local_exit_root.len() != 256 {
        return Err(NoteError::other(alloc::format!(
            "SMT proof local exit root must be exactly 256 felts, got {}",
            params.smt_proof_local_exit_root.len()
        )));
    }
    if params.smt_proof_rollup_exit_root.len() != 256 {
        return Err(NoteError::other(alloc::format!(
            "SMT proof rollup exit root must be exactly 256 felts, got {}",
            params.smt_proof_rollup_exit_root.len()
        )));
    }
    // Create claim inputs matching exactly the agglayer claimAsset function parameters
    let mut claim_storage_items = vec![];

    // 1) PROOF DATA
    // smtProofLocalExitRoot (256 felts) - first SMT proof parameter
    claim_storage_items.extend(params.smt_proof_local_exit_root);
    // smtProofRollupExitRoot (256 felts) - second SMT proof parameter
    claim_storage_items.extend(params.smt_proof_rollup_exit_root);

    // globalIndex (uint256 as 8 u32 felts)
    claim_storage_items.extend(params.global_index);

    // mainnetExitRoot (bytes32 as 8 u32 felts)
    let mainnet_exit_root_felts = bytes32_to_felts(params.mainnet_exit_root);
    claim_storage_items.extend(mainnet_exit_root_felts);

    // rollupExitRoot (bytes32 as 8 u32 felts)
    let rollup_exit_root_felts = bytes32_to_felts(params.rollup_exit_root);
    claim_storage_items.extend(rollup_exit_root_felts);

    // 2) LEAF DATA
    // originNetwork (uint32 as Felt)
    claim_storage_items.push(params.origin_network);

    // originTokenAddress (address as 5 u32 felts)
    let origin_token_address_felts =
        EthAddressFormat::new(*params.origin_token_address).to_elements().to_vec();
    claim_storage_items.extend(origin_token_address_felts);

    // destinationNetwork (uint32 as Felt)
    claim_storage_items.push(params.destination_network);

    // destinationAddress (address as 5 u32 felts)
    // Use AccountId prefix and suffix directly to get [suffix, prefix, 0, 0, 0]
    // TODO: refactor to use destination_address: [u8; 20] instead once conversion function
    // exists [u8; 20] -> [address as 5 Felts]
    let destination_address_felts = vec![
        params.destination_account_id.prefix().as_felt(),
        params.destination_account_id.suffix(),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
    ];
    claim_storage_items.extend(destination_address_felts);

    // amount (uint256 as 8 u32 felts)
    claim_storage_items.extend(params.amount);

    // metadata (fixed size of 8 felts)
    claim_storage_items.extend(params.metadata);

    let padding = vec![Felt::ZERO; 4];
    claim_storage_items.extend(padding);

    // 3) CLAIM NOTE DATA
    // TODO: deterministically compute serial number of p2id hash(GER, leaf index)
    // output_p2id_serial_num (4 felts as Word)
    claim_storage_items.extend(params.p2id_serial_number);

    // agglayer_faucet_account_id (2 felts: prefix and suffix)
    claim_storage_items.push(params.agglayer_faucet_account_id.prefix().as_felt());
    claim_storage_items.push(params.agglayer_faucet_account_id.suffix());

    // output note tag
    claim_storage_items.push(params.output_note_tag.as_u32().into());

    let inputs = NoteStorage::new(claim_storage_items)?;

    let tag = NoteTag::with_account_target(params.agglayer_faucet_account_id);

    let claim_script = claim_script();
    let serial_num = params.rng.draw_word();

    let note_type = NoteType::Public;

    let attachment =
        NetworkAccountTarget::new(params.agglayer_faucet_account_id, NoteExecutionHint::Always)
            .map_err(|e| NoteError::other(e.to_string()))?
            .into();
    // Use a default sender since we don't have sender anymore - create from destination address
    let metadata = NoteMetadata::new(params.claim_note_creator_account_id, note_type, tag)
        .with_attachment(attachment);
    let assets = NoteAssets::new(vec![])?;
    let recipient = NoteRecipient::new(serial_num, claim_script, inputs);

    Ok(Note::new(assets, metadata, recipient))
}

// TESTING HELPERS
// ================================================================================================

#[cfg(any(feature = "testing", test))]
/// Type alias for the complex return type of claim_note_test_inputs.
///
/// Contains:
/// - smt_proof_local_exit_root: `Vec<Felt>` (256 felts)
/// - smt_proof_rollup_exit_root: `Vec<Felt>` (256 felts)
/// - global_index: [Felt; 8]
/// - mainnet_exit_root: [u8; 32]
/// - rollup_exit_root: [u8; 32]
/// - origin_network: Felt
/// - origin_token_address: [u8; 20]
/// - destination_network: Felt
/// - destination_address: [u8; 20]
/// - amount: [Felt; 8]
/// - metadata: [Felt; 8]
pub type ClaimNoteTestInputs = (
    Vec<Felt>,
    Vec<Felt>,
    [Felt; 8],
    [u8; 32],
    [u8; 32],
    Felt,
    [u8; 20],
    Felt,
    [u8; 20],
    [Felt; 8],
    [Felt; 8],
);

#[cfg(any(feature = "testing", test))]
/// Returns dummy test inputs for creating CLAIM notes.
///
/// This is a convenience function for testing that provides realistic dummy data
/// for all the agglayer claimAsset function inputs.
///
/// # Parameters
/// - `amount`: The amount as a single Felt for Miden operations
/// - `destination_account_id`: The destination account ID to convert to address bytes
///
/// # Returns
/// A tuple containing:
/// - smt_proof_local_exit_root: `Vec<Felt>` (256 felts)
/// - smt_proof_rollup_exit_root: `Vec<Felt>` (256 felts)
/// - global_index: [Felt; 8]
/// - mainnet_exit_root: [u8; 32]
/// - rollup_exit_root: [u8; 32]
/// - origin_network: Felt
/// - origin_token_address: [u8; 20]
/// - destination_network: Felt
/// - destination_address: [u8; 20]
/// - amount: [Felt; 8]
/// - metadata: [Felt; 8]
pub fn claim_note_test_inputs(
    amount: Felt,
    destination_account_id: AccountId,
) -> ClaimNoteTestInputs {
    // Create SMT proofs with 256 felts each (32 bytes32 values * 8 u32 per bytes32)
    let smt_proof_local_exit_root = vec![Felt::new(0); 256];
    let smt_proof_rollup_exit_root = vec![Felt::new(0); 256];
    let global_index = [
        Felt::new(12345),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
    ];

    let mainnet_exit_root: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    let rollup_exit_root: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ];

    let origin_network = Felt::new(1);

    let origin_token_address: [u8; 20] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];

    let destination_network = Felt::new(2);

    // Convert AccountId to destination address bytes
    let destination_address =
        EthAddressFormat::from_account_id(destination_account_id).into_bytes();

    // Convert amount Felt to u256 array for agglayer
    let amount_u256 = [
        amount,
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
    ];
    let metadata: [Felt; 8] = [Felt::new(0); 8];

    (
        smt_proof_local_exit_root,
        smt_proof_rollup_exit_root,
        global_index,
        mainnet_exit_root,
        rollup_exit_root,
        origin_network,
        origin_token_address,
        destination_network,
        destination_address,
        amount_u256,
        metadata,
    )
}
