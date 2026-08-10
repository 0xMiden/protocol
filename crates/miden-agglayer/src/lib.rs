#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;

use miden_core::{Felt, Word};
use miden_protocol::account::{AccountBuilder, AccountComponent, AccountId};
use miden_protocol::assembly::Path;
use miden_protocol::asset::TokenSymbol;
use miden_protocol::note::NoteScript;
use miden_protocol::vm::Package;
use miden_standards::account::access::{
    Authority,
    Ownable2Step,
    Pausable,
    PausableManager,
    RoleBasedAccessControl,
    RoleConfig,
};
use miden_standards::account::auth::NetworkAccount;
use miden_standards::account::fees::{ConstantFeeManager, FeePolicyManager};
use miden_standards::account::policies::{
    BurnAllowAll,
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_utils_sync::LazyLock;

pub mod agglayer_note;
pub mod b2agg_note;
pub mod bridge;
pub mod claim_note;
pub mod config_note;
pub mod costs;
pub mod deregister_note;
pub mod errors;
pub mod eth_types;
pub mod faucet;
mod ger_note;
pub mod remove_ger_note;
#[cfg(any(feature = "testing", test))]
pub mod testing;
pub mod update_ger_note;
pub mod utils;

pub use agglayer_note::AgglayerNote;
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
pub use eth_types::{GlobalIndex, GlobalIndexError, MetadataHash};
pub use faucet::{AggLayerFaucet, AgglayerFaucetError};
pub use remove_ger_note::RemoveGerNote;
pub use update_ger_note::UpdateGerNote;
pub use utils::Keccak256Output;

// AGGLAYER ACCOUNT COMPONENTS
// ================================================================================================

static AGGLAYER_PACKAGE: LazyLock<Package> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/miden-agglayer.masp"));
    Package::read_from_bytes_trusted(bytes).expect("shipped AggLayer package is well-formed")
});

static BRIDGE_COMPONENT_PACKAGE: LazyLock<Package> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/miden-agglayer-bridge.masp"));
    Package::read_from_bytes_trusted(bytes)
        .expect("shipped bridge component package is well-formed")
});

static FAUCET_COMPONENT_PACKAGE: LazyLock<Package> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/miden-agglayer-faucet.masp"));
    Package::read_from_bytes_trusted(bytes)
        .expect("shipped faucet component package is well-formed")
});

/// Returns the AggLayer package containing all agglayer modules, including the note scripts.
///
/// The note scripts this crate builds are external references into this package rather than
/// self-contained copies of it, so it must be registered with the MAST store of any executor that
/// runs AggLayer notes. This mirrors the standard note scripts, which are external references into
/// the standards library. `TransactionMastStore::new` preloads both packages, so the in-repo
/// prover and test executors resolve AggLayer notes automatically; a downstream executor that
/// supplies its own `DataStore` must register this package into it (e.g. via
/// `TransactionMastStore::insert_package`), exactly as it must already register the standards
/// package to run standard notes.
pub fn agglayer_package() -> Package {
    AGGLAYER_PACKAGE.clone()
}

/// Resolves the note script exported at `path` from the AggLayer package.
///
/// `path` must be the fully qualified path of a procedure carrying the `@note_script` attribute,
/// e.g. `::agglayer::notes::claim::main`.
pub(crate) fn note_script(path: &str) -> NoteScript {
    NoteScript::from_package_reference(&AGGLAYER_PACKAGE, Path::new(path))
        .expect("agglayer package contains the note script procedure")
}

/// Returns the Bridge component package.
fn agglayer_bridge_component_package() -> Package {
    BRIDGE_COMPONENT_PACKAGE.clone()
}

/// Returns the Faucet component package.
fn agglayer_faucet_component_package() -> Package {
    FAUCET_COMPONENT_PACKAGE.clone()
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
/// - `initial_supply`: Initial outstanding token supply (0 for new faucets)
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
    initial_supply: Felt,
) -> AccountComponent {
    let symbol = TokenSymbol::new(token_symbol).expect("token symbol should be valid");
    AggLayerFaucet::new(symbol, decimals, max_supply, initial_supply)
        .expect("agglayer faucet metadata should be valid")
        .into()
}

impl AggLayerBridge {
    /// Returns an [`AccountBuilder`] for a bridge account with the standard configuration;
    /// finish with `build()` for a new production account or `build_existing()` in tests.
    ///
    /// The bridge starts with an empty faucet registry. Faucets are registered at runtime via
    /// CONFIG_AGG_BRIDGE notes that call `bridge_config::register_faucet`.
    ///
    /// Here `admin` is seeded as the initial member of the built-in `ADMIN` role, which
    /// administers the operational roles in case they don't have their own administrators, and
    /// `roles` seeds the initial holders of the `FAUCET_MNGR`, `GER_INJECTOR`, and `GER_REMOVER`
    /// roles that gate the bridge's privileged procedures.
    ///
    /// `network_id` is the AggLayer network ID assigned to the Miden chain; it is written to the
    /// bridge's [`AggLayerBridge::network_id_slot_name`] storage slot at account creation.
    ///
    /// `fee_policy_manager` prices the notes the bridge consumes and must cover every root
    /// returned by [`AggLayerBridge::allowed_notes`]; production callers should normally
    /// construct it with `NetworkNotePricer::agglayer_bridge_fee_policy_manager` from the
    /// network's current fee parameters.
    ///
    /// The builder is pre-wired with the [`AuthNetworkAccount`] auth component, initialized with
    /// [`AggLayerBridge::allowed_notes()`] so the bridge only accepts its sanctioned input notes.
    /// The tx-script allowlist contains only the canonical `ExpirationTransactionScript` so the
    /// network transaction builder can bound how long the bridge's transactions stay valid.
    ///
    /// The bridge also installs the [`Pausable`] and [`PausableManager`] components for emergency
    /// pauses, gated by the `ADMIN` role via the [`Authority`] unmapped-procedure fallback. While
    /// paused, all bridge entry points abort except `remove_ger`, which stays available so a
    /// fraudulent GER can still be revoked.
    ///
    /// Finally, it installs the [`ConstantFeeManager`]. Its `set_note_fee` procedure updates the
    /// deployed [`BasicConstantFeePolicy`](miden_standards::account::fees::BasicConstantFeePolicy)
    /// schedule and is driven by the allowlisted `CONSTANT_FEE_POLICY_CONFIG` note. The
    /// procedure has no entry in [`AggLayerBridge::procedure_roles`], so it falls back to the
    /// `ADMIN` role. Without it the schedule would be stuck at its deployment prices. A schedule
    /// priced with enough margin may never need an update, but there would be no way to correct
    /// it if the chain's verification base fee rises past that margin.
    ///
    /// [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount
    pub fn account_builder(
        seed: Word,
        admin: AccountId,
        roles: BridgeRoles,
        network_id: u32,
        fee_policy_manager: FeePolicyManager,
    ) -> AccountBuilder {
        NetworkAccount::builder(seed.into(), AggLayerBridge::allowed_notes(), fee_policy_manager)
            .expect("bridge note allowlist is non-empty")
            .with_component(AggLayerBridge::new(network_id))
            .with_component(
                RoleBasedAccessControl::builder()
                    .role(RoleConfig::new(RoleBasedAccessControl::admin_role()).with_member(admin))
                    .roles(roles)
                    .build()
                    .expect("the bridge seeds distinct non-empty roles administered by ADMIN"),
            )
            .with_component(Authority::RbacControlled {
                procedure_roles: AggLayerBridge::procedure_roles(),
            })
            .with_component(Pausable::unpaused())
            .with_component(PausableManager)
            .with_component(ConstantFeeManager::for_basic_constant_fee_policy())
    }
}

impl AggLayerFaucet {
    /// Returns an [`AccountBuilder`] for a faucet account with the specified deployment
    /// configuration; finish with `build()` for a new production account or `build_existing()`
    /// in tests.
    ///
    /// `admin` is seeded as the sole member of the faucet's built-in `ADMIN` role, which gates
    /// every authority-controlled procedure, including the `set_note_fee` that reprices the fee
    /// schedule. `bridge_account_id` stays the [`Ownable2Step`] owner and so remains the only
    /// account that can mint or burn. Production faucets always deploy with an `initial_supply`
    /// of zero; only test fixtures simulate a faucet with outstanding supply.
    ///
    /// `fee_policy_manager` prices the notes the faucet consumes and must cover every root
    /// returned by [`AggLayerFaucet::allowed_notes`]; production callers should normally
    /// construct it with `NetworkNotePricer::agglayer_faucet_fee_policy_manager` from the
    /// network's current fee parameters.
    ///
    /// The builder includes:
    /// - The `AggLayerFaucet` component (token metadata only).
    /// - The `Ownable2Step` component (bridge account ID as owner for mint authorization).
    /// - A [`TokenPolicyManager`] configured with [`MintPolicy::owner_only`] and
    ///   [`BurnPolicy::owner_only`]. The manager additionally registers `BurnAllowAll::root()` as
    ///   an allowed burn policy so the owner can open burns at runtime via `set_burn_policy`. The
    ///   active mint policy component (`MintOwnerOnly`) and burn policy component (`BurnOwnerOnly`)
    ///   are produced by the manager; `BurnAllowAll` is installed separately as the additional
    ///   allowed burn policy procedure.
    /// - The [`RoleBasedAccessControl`] stack, seeding `admin` as the sole member of the built-in
    ///   `ADMIN` role, with [`Authority::RbacControlled`] and an empty procedure-role map so every
    ///   authority-gated procedure resolves to `ADMIN` through the unmapped-procedure fallback.
    /// - The [`ConstantFeeManager`], whose `ADMIN`-gated `set_note_fee` can reprice the deployed
    ///   [`BasicConstantFeePolicy`](miden_standards::account::fees::BasicConstantFeePolicy)
    ///   schedule, driven by the allowlisted `CONSTANT_FEE_POLICY_CONFIG` note.
    /// - The network-account auth component, installed via [`NetworkAccount::builder`] with
    ///   [`AggLayerFaucet::allowed_notes()`]. The tx-script allowlist contains only the canonical
    ///   [`ExpirationTransactionScript`](miden_standards::tx_script::ExpirationTransactionScript).
    ///
    /// Minting and burning are authorized independently of [`Authority`]: `MintOwnerOnly` and
    /// `BurnOwnerOnly` call `ownable2step::assert_sender_is_owner` directly, so they remain gated
    /// on the bridge as the [`Ownable2Step`] owner. `admin` therefore administers the faucet's
    /// configuration (its fee schedule, its policies and its metadata) without gaining the
    /// ability to mint, while the bridge keeps minting exactly as before. The [`Ownable2Step`]
    /// transfer procedures are owner-gated as well, so `admin` cannot change the owner either.
    ///
    /// # Panics
    /// Panics if `token_symbol` is not a valid token symbol, or if the token metadata is invalid,
    /// e.g. `max_supply` exceeds the maximum asset amount or `initial_supply` exceeds
    /// `max_supply`.
    #[allow(clippy::too_many_arguments)]
    pub fn account_builder(
        seed: Word,
        token_symbol: &str,
        decimals: u8,
        max_supply: Felt,
        initial_supply: Felt,
        admin: AccountId,
        bridge_account_id: AccountId,
        fee_policy_manager: FeePolicyManager,
    ) -> AccountBuilder {
        let agglayer_component =
            create_agglayer_faucet_component(token_symbol, decimals, max_supply, initial_supply);

        // `allow_all` is explicitly registered as Reserved so the owner can open burns at runtime
        // via `set_burn_policy`.
        let token_policy_manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::owner_only())
            .active_burn_policy(BurnPolicy::owner_only())
            .allowed_burn_policy(BurnPolicy::allow_all())
            .active_send_policy(TransferPolicy::allow_all())
            .active_receive_policy(TransferPolicy::allow_all())
            .build();

        NetworkAccount::builder(seed.into(), AggLayerFaucet::allowed_notes(), fee_policy_manager)
            .expect("faucet note allowlist is non-empty")
            .with_component(agglayer_component)
            .with_component(Ownable2Step::new(bridge_account_id))
            .with_component(
                RoleBasedAccessControl::with_admins([admin])
                    .expect("the faucet seeds a non-empty ADMIN role"),
            )
            .with_component(Authority::RbacControlled { procedure_roles: BTreeMap::new() })
            .with_components(token_policy_manager)
            .with_component(BurnAllowAll)
            .with_component(ConstantFeeManager::for_basic_constant_fee_policy())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use miden_standards::tx_script::ExpirationTransactionScript;

    use super::*;
    use crate::testing::{
        create_existing_agglayer_faucet,
        create_existing_bridge_account_with_roles,
    };

    /// Both agglayer network accounts allowlist the canonical [`ExpirationTransactionScript`],
    /// which the network transaction builder attaches to every network transaction.
    #[test]
    fn agglayer_accounts_allowlist_expiration_tx_script() {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();

        let bridge = create_existing_bridge_account_with_roles(Word::default(), id, id, id, id, 77);
        let faucet = create_existing_agglayer_faucet(
            Word::default(),
            "AGG",
            6,
            Felt::from(1000u32),
            Felt::ZERO,
            id,
        );

        for account in [bridge, faucet] {
            let network_account = NetworkAccount::try_from(account).unwrap();
            assert!(network_account.allows_tx_script(&ExpirationTransactionScript::script_root()));
        }
    }
}
