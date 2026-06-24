extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, ONE, Word, ZERO};
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account,
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    RoleSymbol,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::crypto::hash::poseidon2::Poseidon2;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::access::RoleAssignment;
use miden_utils_sync::LazyLock;
use thiserror::Error;

use super::agglayer_bridge_component_library;
use crate::claim_note::CgiChainHash;
use crate::utils::Keccak256Output;

/// Removed-GER hash chain representation (32-byte Keccak256 hash)
pub type RemovedGerHashChain = Keccak256Output;
pub use crate::{
    B2AggNote,
    ClaimNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    EthAddress,
    EthAmount,
    EthAmountError,
    EthEmbeddedAccountId,
    ExitRoot,
    GlobalIndex,
    GlobalIndexError,
    LeafData,
    MetadataHash,
    ProofData,
    RemoveGerNote,
    SmtNode,
    UpdateGerNote,
};

// CONSTANTS
// ================================================================================================
// Include the generated agglayer constants
include!(concat!(env!("OUT_DIR"), "/agglayer_constants.rs"));

// AGGLAYER BRIDGE STRUCT
// ================================================================================================

// bridge config
// ------------------------------------------------------------------------------------------------

static GER_MAP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::ger_map")
        .expect("GER map storage slot name should be valid")
});
static REMOVED_GER_HASH_CHAIN_LO_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::removed_ger_hash_chain_lo")
        .expect("removed GER hash chain lo storage slot name should be valid")
});
static REMOVED_GER_HASH_CHAIN_HI_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::removed_ger_hash_chain_hi")
        .expect("removed GER hash chain hi storage slot name should be valid")
});
static FAUCET_REGISTRY_MAP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::faucet_registry_map")
        .expect("faucet registry map storage slot name should be valid")
});
static TOKEN_REGISTRY_MAP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::token_registry_map")
        .expect("token registry map storage slot name should be valid")
});
static FAUCET_METADATA_MAP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::faucet_metadata_map")
        .expect("faucet metadata map storage slot name should be valid")
});

// bridge in
// ------------------------------------------------------------------------------------------------

static CLAIM_NULLIFIERS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::claim_nullifiers")
        .expect("claim nullifiers storage slot name should be valid")
});
static CGI_CHAIN_HASH_LO_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::cgi_chain_hash_lo")
        .expect("CGI chain hash_lo storage slot name should be valid")
});
static CGI_CHAIN_HASH_HI_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::cgi_chain_hash_hi")
        .expect("CGI chain hash_hi storage slot name should be valid")
});

// bridge out
// ------------------------------------------------------------------------------------------------

static LET_FRONTIER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::let_frontier")
        .expect("LET frontier storage slot name should be valid")
});
static LET_ROOT_LO_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::let_root_lo")
        .expect("LET root_lo storage slot name should be valid")
});
static LET_ROOT_HI_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::let_root_hi")
        .expect("LET root_hi storage slot name should be valid")
});
static LET_NUM_LEAVES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::let_num_leaves")
        .expect("LET num_leaves storage slot name should be valid")
});

// BRIDGE RBAC ROLES
// ================================================================================================

// Namespace of the assembled bridge account component library (the `asm/components/bridge.masm`
// wrapper). Procedure roots are resolved as `<namespace>::<proc_name>`.
const BRIDGE_COMPONENT_NAMESPACE: &str = "bridge";

static FAUCET_ADMIN_ROLE: LazyLock<RoleSymbol> = LazyLock::new(|| {
    RoleSymbol::new("FAUCET_ADMIN").expect("FAUCET_ADMIN role symbol should be valid")
});
static GER_INJECTOR_ROLE: LazyLock<RoleSymbol> = LazyLock::new(|| {
    RoleSymbol::new("GER_INJECTOR").expect("GER_INJECTOR role symbol should be valid")
});
static GER_REMOVER_ROLE: LazyLock<RoleSymbol> = LazyLock::new(|| {
    RoleSymbol::new("GER_REMOVER").expect("GER_REMOVER role symbol should be valid")
});

static REGISTER_FAUCET_ROOT: LazyLock<AccountProcedureRoot> =
    LazyLock::new(|| bridge_procedure_root("register_faucet"));
static STORE_FAUCET_METADATA_HASH_ROOT: LazyLock<AccountProcedureRoot> =
    LazyLock::new(|| bridge_procedure_root("store_faucet_metadata_hash"));
static UPDATE_GER_ROOT: LazyLock<AccountProcedureRoot> =
    LazyLock::new(|| bridge_procedure_root("update_ger"));
static REMOVE_GER_ROOT: LazyLock<AccountProcedureRoot> =
    LazyLock::new(|| bridge_procedure_root("remove_ger"));

/// A privileged AggLayer bridge role together with the account that initially holds it.
///
/// Used to seed the bridge account's RBAC role membership at creation. Each variant maps to a
/// distinct role symbol and gates a specific set of bridge procedures:
/// - [`BridgeRoleMember::FaucetAdmin`] (`FAUCET_ADMIN`) gates `register_faucet` and
///   `store_faucet_metadata_hash`.
/// - [`BridgeRoleMember::GerInjector`] (`GER_INJECTOR`) gates `update_ger`.
/// - [`BridgeRoleMember::GerRemover`] (`GER_REMOVER`) gates `remove_ger`.
///
/// Pass several entries with the same variant to seed multiple holders of a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeRoleMember {
    /// Holder of the `FAUCET_ADMIN` role.
    FaucetAdmin(AccountId),
    /// Holder of the `GER_INJECTOR` role.
    GerInjector(AccountId),
    /// Holder of the `GER_REMOVER` role.
    GerRemover(AccountId),
}

impl BridgeRoleMember {
    /// Returns the role symbol of this role.
    pub fn role_symbol(&self) -> RoleSymbol {
        match self {
            BridgeRoleMember::FaucetAdmin(_) => AggLayerBridge::faucet_admin_role(),
            BridgeRoleMember::GerInjector(_) => AggLayerBridge::ger_injector_role(),
            BridgeRoleMember::GerRemover(_) => AggLayerBridge::ger_remover_role(),
        }
    }

    /// Returns the account ID that holds the role.
    pub fn account_id(&self) -> AccountId {
        match self {
            BridgeRoleMember::FaucetAdmin(id)
            | BridgeRoleMember::GerInjector(id)
            | BridgeRoleMember::GerRemover(id) => *id,
        }
    }
}

/// An [`AccountComponent`] implementing the AggLayer Bridge.
///
/// It reexports the procedures from `agglayer::bridge`. When linking against this
/// component, the `agglayer` library must be available to the assembler.
/// The procedures of this component are:
/// - `register_faucet`, which registers a faucet in the bridge.
/// - `update_ger`, which injects a new GER into the storage map.
/// - `remove_ger`, which removes a GER from the storage map and folds it into the running
///   removed-GER keccak256 hash chain.
/// - `bridge_out`, which bridges an asset out of Miden to the destination network.
/// - `claim`, which validates a claim against the AggLayer bridge and creates a MINT note for the
///   AggLayer Faucet.
///
/// ## Access control
///
/// The bridge's privileged roles are managed by the account's RBAC stack (`Ownable2Step` +
/// `RoleBasedAccessControl` + `Authority`), installed alongside this component at account
/// creation, rather than stored as plain account IDs in the bridge component. The role-gated
/// procedures (`register_faucet`, `store_faucet_metadata_hash`, `update_ger`, `remove_ger`) call
/// `authority::assert_authorized`, which requires the note sender to hold the role mapped to the
/// procedure. See [`BridgeRoleMember`] and [`AggLayerBridge::procedure_roles`].
///
/// ## Storage Layout
///
/// - [`Self::ger_map_slot_name`]: Stores the GERs.
/// - [`Self::removed_ger_hash_chain_lo_slot_name`]: Stores the lower 128 bits of the removed-GER
///   keccak256 hash chain.
/// - [`Self::removed_ger_hash_chain_hi_slot_name`]: Stores the upper 128 bits of the removed-GER
///   keccak256 hash chain.
/// - [`Self::faucet_registry_map_slot_name`]: Stores the faucet registry map.
/// - [`Self::token_registry_map_slot_name`]: Stores the token address → faucet ID map.
/// - [`Self::faucet_metadata_map_slot_name`]: Stores conversion metadata (origin address, origin
///   network, scale, metadata hash) for all registered faucets, keyed by sub-key scheme based on
///   faucet ID.
/// - [`Self::claim_nullifiers_slot_name`]: Stores the CLAIM note nullifiers map (RPO(leaf_index,
///   source_bridge_network) → \[1, 0, 0, 0\]).
/// - [`Self::cgi_chain_hash_lo_slot_name`]: Stores the lower 128 bits of the CGI chain hash.
/// - [`Self::cgi_chain_hash_hi_slot_name`]: Stores the upper 128 bits of the CGI chain hash.
/// - [`Self::let_frontier_slot_name`]: Stores the Local Exit Tree (LET) frontier.
/// - [`Self::let_root_lo_slot_name`]: Stores the lower 128 bits of the LET root.
/// - [`Self::let_root_hi_slot_name`]: Stores the upper 128 bits of the LET root.
/// - [`Self::let_num_leaves_slot_name`]: Stores the number of leaves in the LET frontier.
///
/// The bridge starts with an empty faucet registry; faucets are registered at runtime via
/// CONFIG_AGG_BRIDGE notes.
///
/// Claim validation compares the leaf's `destination_network` to the global MASM constant
/// `agglayer::common::constants::MIDEN_NETWORK_ID`. Rust exposes the same value as
/// [`Self::MIDEN_NETWORK_ID`] from generated `agglayer_constants.rs` file.
#[derive(Debug, Clone, Copy, Default)]
pub struct AggLayerBridge;

impl AggLayerBridge {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// AggLayer-assigned network ID for this Miden chain.
    ///
    /// Matches `const MIDEN_NETWORK_ID` in `asm/agglayer/common/constants.masm`.
    pub const MIDEN_NETWORK_ID: u32 = MIDEN_NETWORK_ID;

    const REGISTERED_GER_MAP_VALUE: Word = Word::new([ONE, ZERO, ZERO, ZERO]);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new AggLayer bridge component.
    ///
    /// The bridge's privileged roles (faucet admin, GER injector, GER remover) are not part of
    /// this component; they are managed by the account's RBAC / `Authority` components and seeded
    /// at account creation. See [`create_bridge_account`][crate::create_bridge_account].
    pub fn new() -> Self {
        Self
    }

    // RBAC ROLES
    // --------------------------------------------------------------------------------------------

    /// Returns the `FAUCET_ADMIN` role symbol. Holders may register faucets and store faucet
    /// metadata (`register_faucet`, `store_faucet_metadata_hash`).
    pub fn faucet_admin_role() -> RoleSymbol {
        FAUCET_ADMIN_ROLE.clone()
    }

    /// Returns the `GER_INJECTOR` role symbol. Holders may inject GERs (`update_ger`).
    pub fn ger_injector_role() -> RoleSymbol {
        GER_INJECTOR_ROLE.clone()
    }

    /// Returns the `GER_REMOVER` role symbol. Holders may remove GERs (`remove_ger`).
    pub fn ger_remover_role() -> RoleSymbol {
        GER_REMOVER_ROLE.clone()
    }

    /// Returns the procedure root of the bridge's `register_faucet` procedure.
    pub fn register_faucet_root() -> AccountProcedureRoot {
        *REGISTER_FAUCET_ROOT
    }

    /// Returns the procedure root of the bridge's `store_faucet_metadata_hash` procedure.
    pub fn store_faucet_metadata_hash_root() -> AccountProcedureRoot {
        *STORE_FAUCET_METADATA_HASH_ROOT
    }

    /// Returns the procedure root of the bridge's `update_ger` procedure.
    pub fn update_ger_root() -> AccountProcedureRoot {
        *UPDATE_GER_ROOT
    }

    /// Returns the procedure root of the bridge's `remove_ger` procedure.
    pub fn remove_ger_root() -> AccountProcedureRoot {
        *REMOVE_GER_ROOT
    }

    /// Returns the fixed procedure-to-role map used to configure the account's `Authority`
    /// (`RbacControlled`) component. Each role-gated bridge procedure is mapped to the role
    /// required to invoke it.
    pub fn procedure_roles() -> BTreeMap<AccountProcedureRoot, RoleSymbol> {
        BTreeMap::from([
            (Self::register_faucet_root(), Self::faucet_admin_role()),
            (Self::store_faucet_metadata_hash_root(), Self::faucet_admin_role()),
            (Self::update_ger_root(), Self::ger_injector_role()),
            (Self::remove_ger_root(), Self::ger_remover_role()),
        ])
    }

    /// Groups the given role members into [`RoleAssignment`]s for seeding the account's RBAC
    /// component (one assignment per role, in faucet-admin / GER-injector / GER-remover order).
    /// Roles with no provided members are omitted.
    pub fn rbac_role_assignments(members: &[BridgeRoleMember]) -> Vec<RoleAssignment> {
        let mut faucet_admins = Vec::new();
        let mut ger_injectors = Vec::new();
        let mut ger_removers = Vec::new();
        for member in members {
            match member {
                BridgeRoleMember::FaucetAdmin(id) => faucet_admins.push(*id),
                BridgeRoleMember::GerInjector(id) => ger_injectors.push(*id),
                BridgeRoleMember::GerRemover(id) => ger_removers.push(*id),
            }
        }

        let mut assignments = Vec::new();
        if !faucet_admins.is_empty() {
            assignments.push(RoleAssignment::new(Self::faucet_admin_role(), faucet_admins));
        }
        if !ger_injectors.is_empty() {
            assignments.push(RoleAssignment::new(Self::ger_injector_role(), ger_injectors));
        }
        if !ger_removers.is_empty() {
            assignments.push(RoleAssignment::new(Self::ger_remover_role(), ger_removers));
        }
        assignments
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    // --- bridge config ----

    /// Storage slot name for the GERs map.
    pub fn ger_map_slot_name() -> &'static StorageSlotName {
        &GER_MAP_SLOT_NAME
    }

    /// Storage slot name for the lower 128 bits of the removed-GER keccak256 hash chain.
    pub fn removed_ger_hash_chain_lo_slot_name() -> &'static StorageSlotName {
        &REMOVED_GER_HASH_CHAIN_LO_SLOT_NAME
    }

    /// Storage slot name for the upper 128 bits of the removed-GER keccak256 hash chain.
    pub fn removed_ger_hash_chain_hi_slot_name() -> &'static StorageSlotName {
        &REMOVED_GER_HASH_CHAIN_HI_SLOT_NAME
    }

    /// Storage slot name for the faucet registry map.
    pub fn faucet_registry_map_slot_name() -> &'static StorageSlotName {
        &FAUCET_REGISTRY_MAP_SLOT_NAME
    }

    /// Storage slot name for the token registry map.
    pub fn token_registry_map_slot_name() -> &'static StorageSlotName {
        &TOKEN_REGISTRY_MAP_SLOT_NAME
    }

    /// Storage slot name for the faucet metadata map.
    ///
    /// This map stores conversion metadata (origin address, origin network, scale, metadata hash)
    /// for all registered faucets, keyed by sub-key scheme based on faucet ID.
    pub fn faucet_metadata_map_slot_name() -> &'static StorageSlotName {
        &FAUCET_METADATA_MAP_SLOT_NAME
    }

    // --- bridge in --------

    /// Storage slot name for the CLAIM note nullifiers map.
    pub fn claim_nullifiers_slot_name() -> &'static StorageSlotName {
        &CLAIM_NULLIFIERS_SLOT_NAME
    }

    /// Storage slot name for the lower 128 bits of the CGI chain hash.
    pub fn cgi_chain_hash_lo_slot_name() -> &'static StorageSlotName {
        &CGI_CHAIN_HASH_LO_SLOT_NAME
    }

    /// Storage slot name for the upper 128 bits of the CGI chain hash.
    pub fn cgi_chain_hash_hi_slot_name() -> &'static StorageSlotName {
        &CGI_CHAIN_HASH_HI_SLOT_NAME
    }

    // --- bridge out -------

    /// Storage slot name for the Local Exit Tree (LET) frontier.
    pub fn let_frontier_slot_name() -> &'static StorageSlotName {
        &LET_FRONTIER_SLOT_NAME
    }

    /// Storage slot name for the lower 32 bits of the LET root.
    pub fn let_root_lo_slot_name() -> &'static StorageSlotName {
        &LET_ROOT_LO_SLOT_NAME
    }

    /// Storage slot name for the upper 32 bits of the LET root.
    pub fn let_root_hi_slot_name() -> &'static StorageSlotName {
        &LET_ROOT_HI_SLOT_NAME
    }

    /// Storage slot name for the number of leaves in the LET frontier.
    pub fn let_num_leaves_slot_name() -> &'static StorageSlotName {
        &LET_NUM_LEAVES_SLOT_NAME
    }

    // ALLOWED NOTES
    // --------------------------------------------------------------------------------------------

    /// Returns the set of input-note script roots that AggLayer bridge accounts accept.
    ///
    /// The bridge's [`AuthNetworkAccount`] component is initialized with this allowlist, which
    /// means any transaction consuming a note outside this set is rejected before reaching
    /// `output_note::create`.
    ///
    /// [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount
    pub fn allowed_notes() -> BTreeSet<NoteScriptRoot> {
        BTreeSet::from([
            ClaimNote::script_root(),
            B2AggNote::script_root(),
            ConfigAggBridgeNote::script_root(),
            UpdateGerNote::script_root(),
            RemoveGerNote::script_root(),
        ])
    }

    /// Returns a boolean indicating whether the provided GER is present in storage of the provided
    /// bridge account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn is_ger_registered(
        ger: ExitRoot,
        bridge_account: &Account,
    ) -> Result<bool, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(bridge_account)?;

        // Compute the expected GER hash: poseidon2::merge(GER_LOWER, GER_UPPER)
        let ger_lower: Word = ger.to_elements()[0..4].try_into().unwrap();
        let ger_upper: Word = ger.to_elements()[4..8].try_into().unwrap();
        let ger_hash = Poseidon2::merge(&[ger_lower, ger_upper]);

        // Get the value stored by the GER hash. If this GER was registered, the value would be
        // equal to [1, 0, 0, 0]
        let stored_value = bridge_account
            .storage()
            .get_map_item(AggLayerBridge::ger_map_slot_name(), StorageMapKey::from_raw(ger_hash))
            .expect("provided account should have AggLayer Bridge specific storage slots");

        if stored_value == Self::REGISTERED_GER_MAP_VALUE {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Reads the Local Exit Root (double-word) from the bridge account's storage.
    ///
    /// The Local Exit Root is stored in two dedicated value slots:
    /// - [`AggLayerBridge::let_root_lo_slot_name`] — low word of the root
    /// - [`AggLayerBridge::let_root_hi_slot_name`] — high word of the root
    ///
    /// Returns the 256-bit root as 8 `Felt`s: first the 4 elements of `root_lo`, followed by the 4
    /// elements of `root_hi`. For an empty/uninitialized tree, all elements are zeros.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn read_local_exit_root(account: &Account) -> Result<Vec<Felt>, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(account)?;

        let root_lo_slot = AggLayerBridge::let_root_lo_slot_name();
        let root_hi_slot = AggLayerBridge::let_root_hi_slot_name();

        let root_lo = account
            .storage()
            .get_item(root_lo_slot)
            .expect("should be able to read LET root lo");
        let root_hi = account
            .storage()
            .get_item(root_hi_slot)
            .expect("should be able to read LET root hi");

        let mut root = Vec::with_capacity(8);
        root.extend(root_lo.to_vec());
        root.extend(root_hi.to_vec());

        Ok(root)
    }

    /// Returns the number of leaves in the Local Exit Tree (LET) frontier.
    pub fn read_let_num_leaves(account: &Account) -> u64 {
        let num_leaves_slot = AggLayerBridge::let_num_leaves_slot_name();
        let value = account
            .storage()
            .get_item(num_leaves_slot)
            .expect("should be able to read LET num leaves");
        value.to_vec()[0].as_canonical_u64()
    }

    /// Returns the claimed global index (CGI) chain hash from the corresponding storage slot.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn cgi_chain_hash(bridge_account: &Account) -> Result<CgiChainHash, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(bridge_account)?;

        let cgi_chain_hash_lo = bridge_account
            .storage()
            .get_item(AggLayerBridge::cgi_chain_hash_lo_slot_name())
            .expect("failed to get CGI hash chain lo slot");
        let cgi_chain_hash_hi = bridge_account
            .storage()
            .get_item(AggLayerBridge::cgi_chain_hash_hi_slot_name())
            .expect("failed to get CGI hash chain hi slot");

        Ok(CgiChainHash::new(Self::chain_hash_bytes(cgi_chain_hash_lo, cgi_chain_hash_hi)))
    }

    /// Returns the removed-GER keccak256 hash chain from the corresponding storage slots.
    ///
    /// The chain is the running keccak256 of all removed GERs:
    /// `chain_n = keccak256(chain_{n-1} || removed_ger_n)` with `chain_0 = 0...0`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn removed_ger_hash_chain(
        bridge_account: &Account,
    ) -> Result<RemovedGerHashChain, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(bridge_account)?;

        let chain_lo = bridge_account
            .storage()
            .get_item(AggLayerBridge::removed_ger_hash_chain_lo_slot_name())
            .expect("failed to get removed GER hash chain lo slot");
        let chain_hi = bridge_account
            .storage()
            .get_item(AggLayerBridge::removed_ger_hash_chain_hi_slot_name())
            .expect("failed to get removed GER hash chain hi slot");

        Ok(RemovedGerHashChain::new(Self::chain_hash_bytes(chain_lo, chain_hi)))
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Converts a keccak256 hash stored across two lo/hi storage words into its 32-byte form.
    fn chain_hash_bytes(lo: Word, hi: Word) -> [u8; 32] {
        lo.iter()
            .chain(hi.iter())
            .flat_map(|felt| {
                (u32::try_from(felt.as_canonical_u64()).expect("Felt value does not fit into u32"))
                    .to_le_bytes()
            })
            .collect::<Vec<u8>>()
            .try_into()
            .expect("keccak hash should consist of exactly 32 bytes")
    }

    /// Checks that the provided account is an [`AggLayerBridge`] account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account does not have all AggLayer Bridge specific storage slots.
    /// - the code commitment of the provided account does not match the code commitment of the
    ///   [`AggLayerBridge`].
    fn assert_bridge_account(account: &Account) -> Result<(), AgglayerBridgeError> {
        // check that the storage slots are as expected
        Self::assert_storage_slots(account)?;

        // check that the code commitment matches the code commitment of the bridge account
        Self::assert_code_commitment(account)?;

        Ok(())
    }

    /// Checks that the provided account has all storage slots required for the [`AggLayerBridge`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - provided account does not have all AggLayer Bridge specific storage slots.
    fn assert_storage_slots(account: &Account) -> Result<(), AgglayerBridgeError> {
        // get the storage slot names of the provided account
        let account_storage_slot_names: Vec<&StorageSlotName> = account
            .storage()
            .slots()
            .iter()
            .map(|storage_slot| storage_slot.name())
            .collect::<Vec<&StorageSlotName>>();

        // check that all bridge specific storage slots are presented in the provided account
        let are_slots_present = Self::slot_names()
            .iter()
            .all(|slot_name| account_storage_slot_names.contains(slot_name));
        if !are_slots_present {
            return Err(AgglayerBridgeError::StorageSlotsMismatch);
        }

        Ok(())
    }

    /// Checks that the code commitment of the provided account matches the code commitment of the
    /// [`AggLayerBridge`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the code commitment of the provided account does not match the code commitment of the
    ///   [`AggLayerBridge`].
    fn assert_code_commitment(account: &Account) -> Result<(), AgglayerBridgeError> {
        if BRIDGE_CODE_COMMITMENT != account.code().commitment() {
            return Err(AgglayerBridgeError::CodeCommitmentMismatch);
        }

        Ok(())
    }

    /// Returns a vector of all [`AggLayerBridge`] storage slot names.
    fn slot_names() -> Vec<&'static StorageSlotName> {
        vec![
            &*GER_MAP_SLOT_NAME,
            &*LET_FRONTIER_SLOT_NAME,
            &*LET_ROOT_LO_SLOT_NAME,
            &*LET_ROOT_HI_SLOT_NAME,
            &*LET_NUM_LEAVES_SLOT_NAME,
            &*FAUCET_REGISTRY_MAP_SLOT_NAME,
            &*TOKEN_REGISTRY_MAP_SLOT_NAME,
            &*FAUCET_METADATA_MAP_SLOT_NAME,
            &*REMOVED_GER_HASH_CHAIN_LO_SLOT_NAME,
            &*REMOVED_GER_HASH_CHAIN_HI_SLOT_NAME,
            &*CGI_CHAIN_HASH_LO_SLOT_NAME,
            &*CGI_CHAIN_HASH_HI_SLOT_NAME,
            &*CLAIM_NULLIFIERS_SLOT_NAME,
        ]
    }
}

impl From<AggLayerBridge> for AccountComponent {
    fn from(_bridge: AggLayerBridge) -> Self {
        let bridge_storage_slots = vec![
            StorageSlot::with_empty_map(GER_MAP_SLOT_NAME.clone()),
            StorageSlot::with_empty_map(LET_FRONTIER_SLOT_NAME.clone()),
            StorageSlot::with_value(LET_ROOT_LO_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(LET_ROOT_HI_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(LET_NUM_LEAVES_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_empty_map(FAUCET_REGISTRY_MAP_SLOT_NAME.clone()),
            StorageSlot::with_empty_map(TOKEN_REGISTRY_MAP_SLOT_NAME.clone()),
            StorageSlot::with_empty_map(FAUCET_METADATA_MAP_SLOT_NAME.clone()),
            StorageSlot::with_value(REMOVED_GER_HASH_CHAIN_LO_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(REMOVED_GER_HASH_CHAIN_HI_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(CGI_CHAIN_HASH_LO_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(CGI_CHAIN_HASH_HI_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_empty_map(CLAIM_NULLIFIERS_SLOT_NAME.clone()),
        ];
        bridge_component(bridge_storage_slots)
    }
}

// AGGLAYER BRIDGE ERROR
// ================================================================================================

/// AggLayer Bridge related errors.
#[derive(Debug, Error)]
pub enum AgglayerBridgeError {
    #[error(
        "provided account does not have storage slots required for the AggLayer Bridge account"
    )]
    StorageSlotsMismatch,
    #[error(
        "the code commitment of the provided account does not match the code commitment of the AggLayer Bridge account"
    )]
    CodeCommitmentMismatch,
}

// HELPER FUNCTIONS
// ================================================================================================

/// Resolves the [`AccountProcedureRoot`] of a procedure exported by the bridge account component
/// library, by its name (e.g. `update_ger`).
///
/// # Panics
///
/// Panics if the bridge component library does not export a procedure with the given name.
fn bridge_procedure_root(proc_name: &str) -> AccountProcedureRoot {
    let code = AccountComponentCode::from(agglayer_bridge_component_library());
    let path = alloc::format!("{BRIDGE_COMPONENT_NAMESPACE}::{proc_name}");
    code.get_procedure_root_by_path(path.as_str())
        .unwrap_or_else(|| panic!("bridge component library should export `{path}`"))
}

/// Creates an AggLayer Bridge component with the specified storage slots.
fn bridge_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_bridge_component_library();
    let metadata = AccountComponentMetadata::new("agglayer::bridge")
        .with_description("Bridge component for AggLayer");

    AccountComponent::new(library, storage_slots, metadata)
        .expect("bridge component should satisfy the requirements of a valid account component")
}
