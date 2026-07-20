#![no_std]

extern crate alloc;

use alloc::collections::BTreeSet;

use miden_core::{Felt, Word};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::Path;
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::note::NoteScript;
use miden_protocol::vm::Package;
use miden_standards::account::access::{Authority, Ownable2Step, RoleBasedAccessControl};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager};
use miden_standards::account::policies::{
    BurnAllowAll,
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_utils_sync::LazyLock;

pub mod b2agg_note;
pub mod bridge;
pub mod claim_note;
pub mod config_note;
pub mod deregister_note;
pub mod errors;
pub mod eth_types;
pub mod faucet;
mod ger_note;
pub mod remove_ger_note;
#[cfg(feature = "testing")]
pub mod testing;
pub mod update_ger_note;
pub mod utils;

pub use b2agg_note::B2AggNote;
pub use bridge::{AggLayerBridge, AgglayerBridgeError, BridgeRoles, RemovedGerHashChain};
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
pub use deregister_note::DeregisterAggFaucetNote;
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
pub use remove_ger_note::RemoveGerNote;
pub use update_ger_note::UpdateGerNote;
pub use utils::Keccak256Output;

// AGGLAYER ACCOUNT COMPONENTS
// ================================================================================================

static AGGLAYER_LIBRARY: LazyLock<Package> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/miden-agglayer.masp"));
    Package::read_from_bytes_trusted(bytes).expect("shipped AggLayer package is well-formed")
});

static BRIDGE_COMPONENT_LIBRARY: LazyLock<Package> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/miden-agglayer-bridge.masp"));
    Package::read_from_bytes_trusted(bytes)
        .expect("shipped bridge component package is well-formed")
});

static FAUCET_COMPONENT_LIBRARY: LazyLock<Package> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/miden-agglayer-faucet.masp"));
    Package::read_from_bytes_trusted(bytes)
        .expect("shipped faucet component package is well-formed")
});

/// Returns the AggLayer Library containing all agglayer modules, including the note scripts.
///
/// The note scripts this crate builds are external references into this library rather than
/// self-contained copies of it, so it must be registered with the MAST store of any executor that
/// runs AggLayer notes. This mirrors the standard note scripts, which are external references into
/// the standards library. `TransactionMastStore::new` preloads both libraries, so the in-repo
/// prover and test executors resolve AggLayer notes automatically; a downstream executor that
/// supplies its own `DataStore` must register this library into it (e.g. via
/// `TransactionMastStore::insert_package`), exactly as it must already register the standards
/// library to run standard notes.
pub fn agglayer_library() -> Package {
    AGGLAYER_LIBRARY.clone()
}

/// Resolves the note script exported at `path` from the AggLayer library.
///
/// `path` must be the fully qualified path of a procedure carrying the `@note_script` attribute,
/// e.g. `::agglayer::notes::claim::main`.
pub(crate) fn note_script(path: &str) -> NoteScript {
    NoteScript::from_library_reference(&AGGLAYER_LIBRARY, Path::new(path))
        .expect("agglayer library contains the note script procedure")
}

/// Returns the Bridge component library.
fn agglayer_bridge_component_library() -> Package {
    BRIDGE_COMPONENT_LIBRARY.clone()
}

/// Returns the Faucet component library.
fn agglayer_faucet_component_library() -> Package {
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

/// Returns the `FeeManager` installed on the agglayer bridge and faucet accounts so their auth
/// procedure can collect sponsored fees and answer sponsorship fee estimates. The active policy
/// schedules an explicit 0 fee for every note script in `auth`'s allowlist, so it charges and
/// collects nothing while still letting fee estimation resolve every note the account can consume;
/// a real fee faucet and schedule are configured when fees are enabled on these accounts.
///
/// Because every scheduled fee is 0, the fee asset (and hence the placeholder faucet id below)
/// never funds a transfer; only the policy's procedure code contributes to the account code
/// commitment, which `build.rs` mirrors when computing the compile-time commitment constants (the
/// fee schedule entries are storage, so they do not affect the commitment).
fn agglayer_fee_manager(auth: &AuthNetworkAccount) -> FeeManager {
    // A placeholder public faucet id; see the note above on why its value is immaterial.
    let fee_faucet_id = AccountId::from_hex("0xab0000000000cd110000ac000000de")
        .expect("placeholder fee faucet id is valid");

    // A constant fee policy aborts fee estimation for note scripts without a schedule entry, so
    // enumerate the allowlist and schedule each as free.
    let mut constant_fee_policy = ConstantFeePolicy::new(fee_faucet_id);
    for note_script in auth.allowed_notes().allowed_script_roots() {
        constant_fee_policy = constant_fee_policy.with_fee(*note_script, AssetAmount::ZERO);
    }

    FeeManager::builder().active_fee_policy(constant_fee_policy.into()).build()
}

/// Creates a complete bridge account builder with the standard configuration.
///
/// The bridge starts with an empty faucet registry. Faucets are registered at runtime
/// via CONFIG_AGG_BRIDGE notes that call `bridge_config::register_faucet`.
///
/// Here `admin` is seeded as the initial member of the built-in `ADMIN` role, which administers the
/// operational roles in case they don't have their own administrators, and `roles` seeds the
/// initial holders of the `FAUCET_MNGR`, `GER_INJECTOR`, and `GER_REMOVER` roles that gate the
/// bridge's privileged procedures.
///
/// The builder is pre-wired with the [`AuthNetworkAccount`] auth component, initialized with
/// [`AggLayerBridge::allowed_notes()`] so the bridge only accepts its sanctioned input notes.
fn create_bridge_account_builder(
    seed: Word,
    admin: AccountId,
    roles: BridgeRoles,
) -> AccountBuilder {
    let auth = AuthNetworkAccount::with_allowed_notes(AggLayerBridge::allowed_notes())
        .expect("bridge note allowlist is non-empty");

    Account::builder(seed.into())
        .account_type(AccountType::Public)
        .with_component(AggLayerBridge)
        .with_component(RoleBasedAccessControl::new(BTreeSet::from([admin]), roles.role_members()))
        .with_component(Authority::RbacControlled {
            procedure_roles: AggLayerBridge::procedure_roles(),
        })
        .with_components(agglayer_fee_manager(&auth))
        .with_auth_component(auth)
}

/// Creates a new bridge account with the standard configuration.
///
/// This creates a new account suitable for production use. `admin` bootstraps the `ADMIN` role
/// (role administration); the initial operational-role holders are seeded from `roles` (see
/// [`BridgeRoles`]).
pub fn create_bridge_account(seed: Word, admin: AccountId, roles: BridgeRoles) -> Account {
    create_bridge_account_builder(seed, admin, roles)
        .build()
        .expect("bridge account should be valid")
}

/// Creates a complete agglayer faucet account builder with the specified configuration.
///
/// The builder includes:
/// - The `AggLayerFaucet` component (token metadata only).
/// - The `Ownable2Step` component (bridge account ID as owner for mint authorization).
/// - A [`TokenPolicyManager`] (owner-controlled) configured with [`MintPolicy::owner_only`] and
///   [`BurnPolicy::owner_only`]. The manager additionally registers `BurnAllowAll::root()` as an
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
    let token_policy_manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::owner_only())
        .allowed_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build();

    let auth = AuthNetworkAccount::with_allowed_notes(AggLayerFaucet::allowed_notes())
        .expect("faucet note allowlist is non-empty");

    Account::builder(seed.into())
        .account_type(AccountType::Public)
        .with_component(agglayer_component)
        .with_component(Ownable2Step::new(bridge_account_id))
        .with_component(Authority::OwnerControlled)
        .with_components(token_policy_manager)
        .with_component(BurnAllowAll)
        .with_components(agglayer_fee_manager(&auth))
        .with_auth_component(auth)
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

/// Creates an existing agglayer faucet account with the specified configuration and the asset
/// callback flag enabled.
///
/// This creates an existing account suitable for testing scenarios.
#[cfg(any(feature = "testing", test))]
pub fn create_existing_agglayer_faucet_with_callbacks(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
) -> Account {
    use miden_protocol::account::AssetCallbackFlag;

    create_agglayer_faucet_builder(
        seed,
        token_symbol,
        decimals,
        max_supply,
        token_supply,
        bridge_account_id,
    )
    .with_asset_callbacks(AssetCallbackFlag::Enabled)
    .build_existing()
    .expect("agglayer faucet account should be valid")
}
