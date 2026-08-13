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
use miden_standards::account::fees::{
    BasicConstantFeePolicy,
    ConstantFeeManager,
    FeePolicyManager,
};
use miden_standards::account::policies::{
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

fn assert_basic_constant_fee_policy_manager(fee_policy_manager: &FeePolicyManager) {
    let policy_root = BasicConstantFeePolicy::root();
    assert_eq!(
        fee_policy_manager.active_fee_policy(),
        policy_root,
        "AggLayer accounts require BasicConstantFeePolicy as the active fee policy"
    );
    assert_eq!(
        fee_policy_manager.allowed_fee_policies().as_slice(),
        &[policy_root],
        "AggLayer accounts do not support additional fee policies"
    );
}

impl AggLayerBridge {
    /// Returns an [`AccountBuilder`] for a bridge account with the standard configuration.
    ///
    /// `bridge_admin` is the initial member of the bridge's built-in `ADMIN` role. The fee policy
    /// manager must contain only an active [`BasicConstantFeePolicy`] with entries for
    /// [`AggLayerBridge::allowed_notes`].
    ///
    /// # Panics
    ///
    /// Panics if the fee policy manager contains a different or additional fee policy.
    pub fn account_builder(
        seed: Word,
        bridge_admin: AccountId,
        roles: BridgeRoles,
        network_id: u32,
        fee_policy_manager: FeePolicyManager,
    ) -> AccountBuilder {
        assert_basic_constant_fee_policy_manager(&fee_policy_manager);
        NetworkAccount::builder(seed.into(), AggLayerBridge::allowed_notes(), fee_policy_manager)
            .expect("bridge note allowlist is non-empty")
            .with_component(AggLayerBridge::new(network_id))
            .with_component(
                RoleBasedAccessControl::builder()
                    .role(
                        RoleConfig::new(RoleBasedAccessControl::admin_role())
                            .with_member(bridge_admin),
                    )
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
    /// configuration.
    ///
    /// `faucet_admin` is the initial member of the faucet's built-in `ADMIN` role;
    /// `bridge_account_id` is its [`Ownable2Step`] owner. The fee policy manager must contain only
    /// an active [`BasicConstantFeePolicy`] with entries for [`AggLayerFaucet::allowed_notes`].
    ///
    /// # Panics
    ///
    /// Panics if the token metadata is invalid or the fee policy manager contains a different or
    /// additional fee policy.
    #[allow(clippy::too_many_arguments)]
    pub fn account_builder(
        seed: Word,
        token_symbol: &str,
        decimals: u8,
        max_supply: Felt,
        initial_supply: Felt,
        faucet_admin: AccountId,
        bridge_account_id: AccountId,
        fee_policy_manager: FeePolicyManager,
    ) -> AccountBuilder {
        assert_basic_constant_fee_policy_manager(&fee_policy_manager);
        let agglayer_component =
            create_agglayer_faucet_component(token_symbol, decimals, max_supply, initial_supply);

        let token_policy_manager = TokenPolicyManager::builder()
            .active_mint_policy(MintPolicy::owner_only())
            .active_burn_policy(BurnPolicy::owner_only())
            .active_send_policy(TransferPolicy::allow_all())
            .active_receive_policy(TransferPolicy::allow_all())
            .build();

        NetworkAccount::builder(seed.into(), AggLayerFaucet::allowed_notes(), fee_policy_manager)
            .expect("faucet note allowlist is non-empty")
            .with_component(agglayer_component)
            .with_component(Ownable2Step::new(bridge_account_id))
            .with_component(
                RoleBasedAccessControl::with_admins([faucet_admin])
                    .expect("the faucet seeds a non-empty ADMIN role"),
            )
            .with_component(Authority::RbacControlled { procedure_roles: BTreeMap::new() })
            .with_components(token_policy_manager)
            .with_component(ConstantFeeManager::for_basic_constant_fee_policy())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use miden_standards::account::fees::FeePolicy;
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

    #[test]
    #[should_panic(expected = "require BasicConstantFeePolicy")]
    fn agglayer_accounts_reject_a_different_active_fee_policy() {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let policy = FeePolicy::custom(PausableManager::pause_root(), [PausableManager]).unwrap();
        let manager =
            FeePolicyManager::builder().fee_faucet_id(id).active_fee_policy(policy).build();

        assert_basic_constant_fee_policy_manager(&manager);
    }

    #[test]
    #[should_panic(expected = "do not support additional fee policies")]
    fn agglayer_accounts_reject_additional_fee_policies() {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let policy = FeePolicy::custom(PausableManager::pause_root(), [PausableManager]).unwrap();
        let manager = FeePolicyManager::builder()
            .fee_faucet_id(id)
            .active_fee_policy(BasicConstantFeePolicy::new().into())
            .allowed_fee_policy(policy)
            .build();

        assert_basic_constant_fee_policy_manager(&manager);
    }
}
