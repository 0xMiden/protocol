#![no_std]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::String;

use miden_core::{Felt, Word};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId};
use miden_protocol::assembly::Path;
#[cfg(any(feature = "testing", test))]
use miden_protocol::asset::AssetAmount;
use miden_protocol::asset::TokenSymbol;
use miden_protocol::note::NoteScript;
#[cfg(any(feature = "testing", test))]
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::vm::Package;
use miden_standards::account::access::{
    Authority,
    Ownable2Step,
    Pausable,
    PausableManager,
    RoleBasedAccessControl,
};
use miden_standards::account::auth::NetworkAccount;
#[cfg(any(feature = "testing", test))]
use miden_standards::account::fees::BasicConstantFeePolicy;
use miden_standards::account::fees::FeePolicyManager;
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

/// Returns a zero-fee policy manager for tests that exercise AggLayer behavior independently of
/// fee sponsorship. Production constructors require their deployment-time manager explicitly.
#[cfg(any(feature = "testing", test))]
fn testing_zero_fee_policy_manager(allowed_notes: BTreeSet<NoteScriptRoot>) -> FeePolicyManager {
    let fee_faucet_id = AccountId::from_hex("0xab0000000000cd110000ac000000de")
        .expect("placeholder fee faucet id is valid");

    let mut basic_constant_fee_policy = BasicConstantFeePolicy::new();
    for note_script in allowed_notes {
        basic_constant_fee_policy =
            basic_constant_fee_policy.with_fee(note_script, AssetAmount::ZERO);
    }

    FeePolicyManager::builder()
        .active_fee_policy(basic_constant_fee_policy.into())
        .fee_faucet_id(fee_faucet_id)
        .build()
}

/// Builder for an AggLayer bridge account.
///
/// Configure the production fee policy with [`Self::with_fee_policy_manager`] before building.
pub struct AggLayerBridgeAccountBuilder {
    seed: Word,
    admin: AccountId,
    roles: BridgeRoles,
    network_id: u32,
    fee_policy_manager: Option<FeePolicyManager>,
}

impl AggLayerBridgeAccountBuilder {
    fn new(seed: Word, admin: AccountId, roles: BridgeRoles, network_id: u32) -> Self {
        Self {
            seed,
            admin,
            roles,
            network_id,
            fee_policy_manager: None,
        }
    }

    /// Configures the manager that prices the notes consumed by the bridge account.
    ///
    /// Production callers should normally use
    /// `NetworkNotePricer::agglayer_bridge_fee_policy_manager` to construct this value from the
    /// network's current fee parameters.
    #[must_use]
    pub fn with_fee_policy_manager(mut self, fee_policy_manager: FeePolicyManager) -> Self {
        self.fee_policy_manager = Some(fee_policy_manager);
        self
    }

    fn into_account_builder(self) -> AccountBuilder {
        let fee_policy_manager = self
            .fee_policy_manager
            .expect("AggLayer bridge account requires a fee policy manager");
        create_bridge_account_builder(
            self.seed,
            self.admin,
            self.roles,
            self.network_id,
            fee_policy_manager,
        )
    }

    /// Builds a new AggLayer bridge account.
    pub fn build(self) -> Account {
        self.into_account_builder().build().expect("bridge account should be valid")
    }

    /// Builds an existing AggLayer bridge account for tests.
    #[cfg(any(feature = "testing", test))]
    pub fn build_existing(self) -> Account {
        self.into_account_builder()
            .build_existing()
            .expect("bridge account should be valid")
    }
}

impl AggLayerBridge {
    /// Returns a builder for a bridge account with the specified deployment configuration.
    pub fn account_builder(
        seed: Word,
        admin: AccountId,
        roles: BridgeRoles,
        network_id: u32,
    ) -> AggLayerBridgeAccountBuilder {
        AggLayerBridgeAccountBuilder::new(seed, admin, roles, network_id)
    }
}

/// Builder for an AggLayer faucet account.
///
/// Configure the production fee policy with [`Self::with_fee_policy_manager`] before building.
pub struct AggLayerFaucetAccountBuilder {
    seed: Word,
    token_symbol: String,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
    fee_policy_manager: Option<FeePolicyManager>,
    #[cfg(any(feature = "testing", test))]
    asset_callbacks: Option<miden_protocol::account::AssetCallbackFlag>,
}

impl AggLayerFaucetAccountBuilder {
    fn new(
        seed: Word,
        token_symbol: &str,
        decimals: u8,
        max_supply: Felt,
        bridge_account_id: AccountId,
    ) -> Self {
        Self {
            seed,
            token_symbol: token_symbol.into(),
            decimals,
            max_supply,
            token_supply: Felt::ZERO,
            bridge_account_id,
            fee_policy_manager: None,
            #[cfg(any(feature = "testing", test))]
            asset_callbacks: None,
        }
    }

    /// Configures the manager that prices the notes consumed by the faucet account.
    ///
    /// Production callers should normally use
    /// `NetworkNotePricer::agglayer_faucet_fee_policy_manager` to construct this value from the
    /// network's current fee parameters.
    #[must_use]
    pub fn with_fee_policy_manager(mut self, fee_policy_manager: FeePolicyManager) -> Self {
        self.fee_policy_manager = Some(fee_policy_manager);
        self
    }

    /// Sets the initial outstanding token supply for tests that build an existing faucet.
    #[cfg(any(feature = "testing", test))]
    #[must_use]
    pub fn with_token_supply(mut self, token_supply: Felt) -> Self {
        self.token_supply = token_supply;
        self
    }

    /// Configures asset callbacks for tests that build an existing faucet.
    #[cfg(any(feature = "testing", test))]
    #[must_use]
    pub fn with_asset_callbacks(
        mut self,
        asset_callbacks: miden_protocol::account::AssetCallbackFlag,
    ) -> Self {
        self.asset_callbacks = Some(asset_callbacks);
        self
    }

    fn into_account_builder(self) -> AccountBuilder {
        let fee_policy_manager = self
            .fee_policy_manager
            .expect("AggLayer faucet account requires a fee policy manager");
        let builder = create_agglayer_faucet_builder(
            self.seed,
            &self.token_symbol,
            self.decimals,
            self.max_supply,
            self.token_supply,
            self.bridge_account_id,
            fee_policy_manager,
        );

        #[cfg(any(feature = "testing", test))]
        let builder = match self.asset_callbacks {
            Some(asset_callbacks) => builder.with_asset_callbacks(asset_callbacks),
            None => builder,
        };

        builder
    }

    /// Builds a new AggLayer faucet account.
    pub fn build(self) -> Account {
        self.into_account_builder()
            .build()
            .expect("agglayer faucet account should be valid")
    }

    /// Builds an existing AggLayer faucet account for tests.
    #[cfg(any(feature = "testing", test))]
    pub fn build_existing(self) -> Account {
        self.into_account_builder()
            .build_existing()
            .expect("agglayer faucet account should be valid")
    }
}

impl AggLayerFaucet {
    /// Returns a builder for a faucet account with the specified deployment configuration.
    pub fn account_builder(
        seed: Word,
        token_symbol: &str,
        decimals: u8,
        max_supply: Felt,
        bridge_account_id: AccountId,
    ) -> AggLayerFaucetAccountBuilder {
        AggLayerFaucetAccountBuilder::new(
            seed,
            token_symbol,
            decimals,
            max_supply,
            bridge_account_id,
        )
    }
}

/// Creates a complete bridge account builder with the standard configuration.
///
/// The bridge starts with an empty faucet registry. Faucets are registered at runtime via
/// CONFIG_AGG_BRIDGE notes that call `bridge_config::register_faucet`.
///
/// Here `admin` is seeded as the initial member of the built-in `ADMIN` role, which administers the
/// operational roles in case they don't have their own administrators, and `roles` seeds the
/// initial holders of the `FAUCET_MNGR`, `GER_INJECTOR`, and `GER_REMOVER` roles that gate the
/// bridge's privileged procedures.
///
/// `network_id` is the AggLayer network ID assigned to the Miden chain; it is written to the
/// bridge's [`AggLayerBridge::network_id_slot_name`] storage slot at account creation.
///
/// The builder is pre-wired with the [`AuthNetworkAccount`] auth component, initialized with
/// [`AggLayerBridge::allowed_notes()`] so the bridge only accepts its sanctioned input notes. The
/// tx-script allowlist contains only the canonical `ExpirationTransactionScript` so the network
/// transaction builder can bound how long the bridge's transactions stay valid.
///
/// The bridge also installs the [`Pausable`] and [`PausableManager`] components for emergency
/// pauses, gated by the `ADMIN` role via the [`Authority`] unmapped-procedure fallback. While
/// paused, all bridge entry points abort except `remove_ger`, which stays available so a
/// fraudulent GER can still be revoked.
fn create_bridge_account_builder(
    seed: Word,
    admin: AccountId,
    roles: BridgeRoles,
    network_id: u32,
    fee_policy_manager: FeePolicyManager,
) -> AccountBuilder {
    NetworkAccount::builder(seed.into(), AggLayerBridge::allowed_notes(), fee_policy_manager)
        .expect("bridge note allowlist is non-empty")
        .with_component(AggLayerBridge::new(network_id))
        .with_component(RoleBasedAccessControl::new(BTreeSet::from([admin]), roles.role_members()))
        .with_component(Authority::RbacControlled {
            procedure_roles: AggLayerBridge::procedure_roles(),
        })
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
}

/// Creates a new bridge account with the standard configuration.
///
/// This creates a new account suitable for production use. `admin` bootstraps the `ADMIN` role
/// (role administration); the initial operational-role holders are seeded from `roles` (see
/// [`BridgeRoles`]). `network_id` is the AggLayer network ID assigned to the Miden chain. The
/// supplied `fee_policy_manager` must price every root returned by
/// [`AggLayerBridge::fee_policy_notes`].
pub fn create_bridge_account(
    seed: Word,
    admin: AccountId,
    roles: BridgeRoles,
    network_id: u32,
    fee_policy_manager: FeePolicyManager,
) -> Account {
    AggLayerBridge::account_builder(seed, admin, roles, network_id)
        .with_fee_policy_manager(fee_policy_manager)
        .build()
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
/// - The network-account auth component, installed via [`NetworkAccount::builder`] with
///   [`AggLayerFaucet::allowed_notes()`] so the faucet only accepts MINT and BURN notes. The
///   tx-script allowlist contains only the canonical
///   [`ExpirationTransactionScript`](miden_standards::tx_script::ExpirationTransactionScript).
fn create_agglayer_faucet_builder(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
    fee_policy_manager: FeePolicyManager,
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

    NetworkAccount::builder(seed.into(), AggLayerFaucet::allowed_notes(), fee_policy_manager)
        .expect("faucet note allowlist is non-empty")
        .with_component(agglayer_component)
        .with_component(Ownable2Step::new(bridge_account_id))
        .with_component(Authority::OwnerControlled)
        .with_components(token_policy_manager)
        .with_component(BurnAllowAll)
}

/// Creates a new agglayer faucet account with the specified configuration.
///
/// This creates a new account suitable for production use. The supplied `fee_policy_manager` must
/// price every root returned by [`AggLayerFaucet::fee_policy_notes`].
pub fn create_agglayer_faucet(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    bridge_account_id: AccountId,
    fee_policy_manager: FeePolicyManager,
) -> Account {
    AggLayerFaucet::account_builder(seed, token_symbol, decimals, max_supply, bridge_account_id)
        .with_fee_policy_manager(fee_policy_manager)
        .build()
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
    let fee_policy_manager = testing_zero_fee_policy_manager(AggLayerFaucet::fee_policy_notes());
    AggLayerFaucet::account_builder(seed, token_symbol, decimals, max_supply, bridge_account_id)
        .with_token_supply(token_supply)
        .with_fee_policy_manager(fee_policy_manager)
        .build_existing()
}

/// Creates an existing agglayer faucet with an explicitly configured fee policy manager.
#[cfg(any(feature = "testing", test))]
pub fn create_existing_agglayer_faucet_with_fee_policy(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    token_supply: Felt,
    bridge_account_id: AccountId,
    fee_policy_manager: FeePolicyManager,
) -> Account {
    AggLayerFaucet::account_builder(seed, token_symbol, decimals, max_supply, bridge_account_id)
        .with_token_supply(token_supply)
        .with_fee_policy_manager(fee_policy_manager)
        .build_existing()
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

    let fee_policy_manager = testing_zero_fee_policy_manager(AggLayerFaucet::fee_policy_notes());
    AggLayerFaucet::account_builder(seed, token_symbol, decimals, max_supply, bridge_account_id)
        .with_token_supply(token_supply)
        .with_fee_policy_manager(fee_policy_manager)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .build_existing()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use miden_standards::tx_script::ExpirationTransactionScript;

    use super::*;
    use crate::testing::create_existing_bridge_account_with_roles;

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
