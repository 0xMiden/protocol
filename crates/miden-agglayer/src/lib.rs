#![no_std]

extern crate alloc;

use miden_assembly::Library;
use miden_assembly::serde::Deserializable;
use miden_core::{Felt, Word};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::asset::TokenSymbol;
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::policies::{
    BurnAllowAll,
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_utils_sync::LazyLock;

pub mod b2agg_note;
pub mod bridge;
pub mod claim_note;
pub mod config_note;
pub mod errors;
pub mod eth_types;
pub mod faucet;
#[cfg(feature = "testing")]
pub mod testing;
pub mod update_ger_note;
pub mod utils;

pub use b2agg_note::B2AggNote;
pub use bridge::{AggLayerBridge, AgglayerBridgeError};
pub use claim_note::{
    CgiChainHash,
    ClaimNote,
    ClaimNoteStorage,
    ExitRoot,
    LeafData,
    LeafValue,
    ProofData,
    SmtNode,
};
pub use config_note::{ConfigAggBridgeNote, ConversionMetadata};
#[cfg(any(test, feature = "testing"))]
pub use eth_types::GlobalIndexExt;
pub use eth_types::{
    EthAddress,
    EthAmount,
    EthAmountError,
    EthEmbeddedAccountId,
    GlobalIndex,
    GlobalIndexError,
    MetadataHash,
};
pub use faucet::{AggLayerFaucet, AgglayerFaucetError};
pub use update_ger_note::UpdateGerNote;
pub use utils::Keccak256Output;

// AGGLAYER ACCOUNT COMPONENTS
// ================================================================================================

static AGGLAYER_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/agglayer.masl"));
    Library::read_from_bytes(bytes).expect("shipped AggLayer library is well-formed")
});

static BRIDGE_COMPONENT_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/bridge.masl"));
    Library::read_from_bytes(bytes).expect("shipped bridge component library is well-formed")
});

static FAUCET_COMPONENT_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/faucet.masl"));
    Library::read_from_bytes(bytes).expect("shipped faucet component library is well-formed")
});

/// Returns the AggLayer Library containing all agglayer modules.
pub fn agglayer_library() -> Library {
    AGGLAYER_LIBRARY.clone()
}

/// Returns the Bridge component library.
fn agglayer_bridge_component_library() -> Library {
    BRIDGE_COMPONENT_LIBRARY.clone()
}

/// Returns the Faucet component library.
fn agglayer_faucet_component_library() -> Library {
    FAUCET_COMPONENT_LIBRARY.clone()
}

// AGGLAYER ACCOUNT CREATION HELPERS
// ================================================================================================

/// Creates an agglayer faucet account component with the specified configuration.
///
/// The faucet holds only token metadata; conversion metadata (origin address, origin network,
/// scale, metadata hash) lives on the bridge and is populated at registration time.
///
/// # Parameters
/// - `token_symbol`: The symbol for the fungible token (e.g., "AGG")
/// - `decimals`: Number of decimal places for the token
/// - `max_supply`: Maximum supply of the token
/// - `token_supply`: Initial outstanding token supply (0 for new faucets)
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
) -> AccountComponent {
    let symbol = TokenSymbol::new(token_symbol).expect("token symbol should be valid");
    AggLayerFaucet::new(symbol, decimals, max_supply, token_supply)
        .expect("agglayer faucet metadata should be valid")
        .into()
}

/// Creates a complete bridge account builder with the standard configuration.
///
/// The bridge starts with an empty faucet registry. Faucets are registered at runtime
/// via CONFIG_AGG_BRIDGE notes that call `bridge_config::register_faucet`.
///
/// The builder is pre-wired with the [`AuthNetworkAccount`] auth component, initialized with
/// [`AggLayerBridge::allowed_notes()`] so the bridge only accepts its sanctioned input notes.
fn create_bridge_account_builder(
    seed: Word,
    bridge_admin_id: AccountId,
    ger_manager_id: AccountId,
) -> AccountBuilder {
    Account::builder(seed.into())
        .account_type(AccountType::Public)
        .with_component(AggLayerBridge::new(bridge_admin_id, ger_manager_id))
        .with_auth_component(
            AuthNetworkAccount::with_allowed_notes(AggLayerBridge::allowed_notes())
                .expect("bridge note allowlist is non-empty"),
        )
}

/// Creates a new bridge account with the standard configuration.
///
/// This creates a new account suitable for production use.
pub fn create_bridge_account(
    seed: Word,
    bridge_admin_id: AccountId,
    ger_manager_id: AccountId,
) -> Account {
    create_bridge_account_builder(seed, bridge_admin_id, ger_manager_id)
        .build()
        .expect("bridge account should be valid")
}

/// Creates an existing bridge account with the standard configuration.
///
/// This creates an existing account suitable for testing scenarios.
#[cfg(any(feature = "testing", test))]
pub fn create_existing_bridge_account(
    seed: Word,
    bridge_admin_id: AccountId,
    ger_manager_id: AccountId,
) -> Account {
    create_bridge_account_builder(seed, bridge_admin_id, ger_manager_id)
        .build_existing()
        .expect("bridge account should be valid")
}

/// Creates a complete agglayer faucet account builder with the specified configuration.
///
/// The builder includes:
/// - The `AggLayerFaucet` component (token metadata only).
/// - The `Ownable2Step` component (bridge account ID as owner for mint authorization).
/// - A [`TokenPolicyManager`] (owner-controlled) configured with `MintPolicyConfig::OwnerOnly` and
///   `BurnPolicyConfig::OwnerOnly`. The manager additionally registers `BurnAllowAll::root()` as an
///   allowed burn policy so the owner can open burns at runtime via `set_burn_policy`. The active
///   mint policy component (`MintOwnerOnly`) and burn policy component (`BurnOwnerOnly`) are
///   produced by the manager; `BurnAllowAll` is installed separately as the additional allowed burn
///   policy procedure.
/// - The [`AuthNetworkAccount`] auth component, initialized with
///   [`AggLayerFaucet::allowed_notes()`] so the faucet only accepts MINT and BURN notes.
fn create_agglayer_faucet_builder(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
) -> AccountBuilder {
    let agglayer_component =
        create_agglayer_faucet_component(token_symbol, decimals, max_supply, token_supply);

    // `allow_all` is explicitly registered as Reserved so the owner can open burns at runtime
    // via `set_burn_policy`.
    let token_policy_manager = TokenPolicyManager::new()
        .with_mint_policy(MintPolicyConfig::OwnerOnly, PolicyRegistration::Active)
        .expect("active mint policy is registered exactly once")
        .with_burn_policy(BurnPolicyConfig::OwnerOnly, PolicyRegistration::Active)
        .expect("active burn policy is registered exactly once")
        .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Reserved)
        .expect("reserved burn policy registration does not conflict")
        .with_send_policy(TransferPolicy::AllowAll, PolicyRegistration::Active)
        .expect("active send policy is registered exactly once")
        .with_receive_policy(TransferPolicy::AllowAll, PolicyRegistration::Active)
        .expect("active receive policy is registered exactly once");

    Account::builder(seed.into())
        .account_type(AccountType::Public)
        .with_component(agglayer_component)
        .with_component(Ownable2Step::new(bridge_account_id))
        .with_component(Authority::OwnerControlled)
        .with_components(token_policy_manager)
        .with_component(BurnAllowAll)
        .with_auth_component(
            AuthNetworkAccount::with_allowed_notes(AggLayerFaucet::allowed_notes())
                .expect("faucet note allowlist is non-empty"),
        )
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
    create_agglayer_faucet_builder(
        seed,
        token_symbol,
        decimals,
        max_supply,
        Felt::ZERO,
        bridge_account_id,
    )
    .build()
    .expect("agglayer faucet account should be valid")
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
    token_supply: Felt,
    bridge_account_id: AccountId,
) -> Account {
    create_agglayer_faucet_builder(
        seed,
        token_symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_account_id,
    )
    .build_existing()
    .expect("agglayer faucet account should be valid")
}
