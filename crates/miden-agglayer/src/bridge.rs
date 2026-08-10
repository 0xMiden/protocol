extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    RoleSymbol,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScriptRoot};
#[cfg(any(feature = "testing", test))]
use miden_standards::account::access::PausableStorage;
use miden_standards::account::access::RoleConfig;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::note::{
    ConstantFeePolicyConfigNote,
    NetworkAccountTarget,
    NetworkAccountTargetError,
    NoteExecutionHint,
    PauseConfig,
    PauseConfigNote,
    RbacConfigNote,
};
use miden_standards::procedure_root;
use miden_utils_sync::LazyLock;
use thiserror::Error;

use super::agglayer_bridge_component_package;
use crate::utils::Keccak256Output;

/// Removed-GER hash chain representation (32-byte Keccak256 hash)
pub type RemovedGerHashChain = Keccak256Output;
pub use miden_standards::interop::eth::{
    EthAddress,
    EthAmount,
    EthAmountError,
    EthEmbeddedAccountId,
};

pub use crate::{
    B2AggNote,
    ClaimNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    DeregisterAggFaucetNote,
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
static NETWORK_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("agglayer::bridge::network_id")
        .expect("network ID storage slot name should be valid")
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

static FAUCET_MANAGER_ROLE: LazyLock<RoleSymbol> = LazyLock::new(|| {
    RoleSymbol::new("FAUCET_MNGR").expect("FAUCET_MNGR role symbol should be valid")
});
static GER_INJECTOR_ROLE: LazyLock<RoleSymbol> = LazyLock::new(|| {
    RoleSymbol::new("GER_INJECTOR").expect("GER_INJECTOR role symbol should be valid")
});
static GER_REMOVER_ROLE: LazyLock<RoleSymbol> = LazyLock::new(|| {
    RoleSymbol::new("GER_REMOVER").expect("GER_REMOVER role symbol should be valid")
});

/// The assembled bridge account component code, used to resolve the roots of the bridge's
/// role-gated procedures.
static BRIDGE_COMPONENT_CODE: LazyLock<AccountComponentCode> =
    LazyLock::new(|| AccountComponentCode::from(agglayer_bridge_component_package()));

procedure_root!(
    REGISTER_FAUCET_ROOT,
    AggLayerBridge::COMPONENT_NAMESPACE,
    "register_faucet",
    AggLayerBridge::code()
);
procedure_root!(
    STORE_FAUCET_METADATA_HASH_ROOT,
    AggLayerBridge::COMPONENT_NAMESPACE,
    "store_faucet_metadata_hash",
    AggLayerBridge::code()
);
procedure_root!(
    UPDATE_GER_ROOT,
    AggLayerBridge::COMPONENT_NAMESPACE,
    "update_ger",
    AggLayerBridge::code()
);
procedure_root!(
    REMOVE_GER_ROOT,
    AggLayerBridge::COMPONENT_NAMESPACE,
    "remove_ger",
    AggLayerBridge::code()
);
procedure_root!(
    DEREGISTER_FAUCET_ROOT,
    AggLayerBridge::COMPONENT_NAMESPACE,
    "deregister_faucet",
    AggLayerBridge::code()
);

// BRIDGE ROLES
// ================================================================================================

/// The accounts that initially hold each of the bridge's privileged RBAC roles.
///
/// Used to seed the bridge account's RBAC role membership at creation. Each role gates a distinct
/// set of bridge procedures:
/// - `FAUCET_MNGR` gates `register_faucet` and `store_faucet_metadata_hash`.
/// - `GER_INJECTOR` gates `update_ger`.
/// - `GER_REMOVER` gates `remove_ger`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRoles {
    roles: Vec<RoleConfig>,
}

impl BridgeRoles {
    /// Creates the initial bridge role membership from the holders of each role.
    ///
    /// The roles are left administered by the `ADMIN` role.
    ///
    /// # Errors
    ///
    /// Returns [`AgglayerBridgeError::EmptyBridgeRole`] if any of the three roles is given an empty
    /// set of holders.
    pub fn new(
        faucet_managers: BTreeSet<AccountId>,
        ger_injectors: BTreeSet<AccountId>,
        ger_removers: BTreeSet<AccountId>,
    ) -> Result<Self, AgglayerBridgeError> {
        let mut roles = Vec::new();
        for (role, members) in [
            (AggLayerBridge::faucet_manager_role(), &faucet_managers),
            (AggLayerBridge::ger_injector_role(), &ger_injectors),
            (AggLayerBridge::ger_remover_role(), &ger_removers),
        ] {
            if members.is_empty() {
                return Err(AgglayerBridgeError::EmptyBridgeRole(role));
            }
            roles.push(RoleConfig::new(role).with_members(members.iter().copied()));
        }

        Ok(Self { roles })
    }
}

impl IntoIterator for BridgeRoles {
    type Item = RoleConfig;
    type IntoIter = alloc::vec::IntoIter<RoleConfig>;

    fn into_iter(self) -> Self::IntoIter {
        self.roles.into_iter()
    }
}

// AGG LAYER BRIDGE
// ================================================================================================

/// An [`AccountComponent`] implementing the AggLayer Bridge.
///
/// It reexports the procedures from `agglayer::bridge`. When linking against this
/// component, the `agglayer` package must be available to the assembler.
/// The procedures of this component are:
/// - `register_faucet`, which registers a faucet in the bridge.
/// - `deregister_faucet`, which clears a previously-registered faucet from both the faucet registry
///   and token registry maps.
/// - `update_ger`, which injects a new GER into the storage map.
/// - `remove_ger`, which removes a GER from the storage map and folds it into the running
///   removed-GER keccak256 hash chain.
/// - `bridge_out`, which bridges an asset out of Miden to the destination network.
/// - `claim`, which validates a claim against the AggLayer bridge and creates a MINT note for the
///   AggLayer Faucet.
///
/// ## Access control
///
/// The bridge's privileged roles are managed by the account's RBAC stack
/// (`RoleBasedAccessControl` + `Authority`), installed alongside this component at account
/// creation. The role-gated procedures call `authority::assert_authorized`, which requires the note
/// sender to hold the role mapped to the procedure. See [`BridgeRoles`] and
/// [`AggLayerBridge::procedure_roles`].
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
/// - [`Self::network_id_slot_name`]: Stores the bridge's AggLayer network ID.
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
/// CONFIG_AGG_BRIDGE notes and can be removed via DEREGISTER_AGG_FAUCET notes.
///
/// Claim validation compares the leaf's `destination_network` to the bridge's own network ID,
/// which is stored in [`Self::network_id_slot_name`] at account creation and read at runtime by
/// the bridge MASM. The network ID is set once and never mutated, so different deployments (e.g.
/// testnet vs mainnet) can use different IDs.
#[derive(Debug, Clone, Copy)]
pub struct AggLayerBridge {
    network_id: u32,
}

impl AggLayerBridge {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Namespace of the assembled bridge account component package (the
    /// `asm/components/bridge/bridge.masm` wrapper). Procedure roots are resolved as
    /// `<namespace>::<proc_name>`.
    const COMPONENT_NAMESPACE: &'static str = "agglayer::components::bridge";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new AggLayer bridge component with the standard configuration.
    ///
    /// `network_id` is the AggLayer network ID assigned to the Miden chain; it is written to the
    /// [`Self::network_id_slot_name`] storage slot at account creation.
    pub fn new(network_id: u32) -> Self {
        Self { network_id }
    }

    // RBAC ROLES
    // --------------------------------------------------------------------------------------------

    /// Returns the assembled bridge account component code.
    pub fn code() -> &'static AccountComponentCode {
        &BRIDGE_COMPONENT_CODE
    }

    /// Returns the `FAUCET_MNGR` role symbol. Holders may register faucets and store faucet
    /// metadata (`register_faucet`, `store_faucet_metadata_hash`).
    pub fn faucet_manager_role() -> RoleSymbol {
        FAUCET_MANAGER_ROLE.clone()
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

    /// Returns the procedure root of the bridge's `deregister_faucet` procedure.
    pub fn deregister_faucet_root() -> AccountProcedureRoot {
        *DEREGISTER_FAUCET_ROOT
    }

    /// Returns the fixed procedure-to-role map used to configure the account's `Authority`
    /// (`RbacControlled`) component. Each role-gated bridge procedure is mapped to the role
    /// required to invoke it.
    pub fn procedure_roles() -> BTreeMap<AccountProcedureRoot, RoleSymbol> {
        BTreeMap::from([
            (Self::register_faucet_root(), Self::faucet_manager_role()),
            (Self::store_faucet_metadata_hash_root(), Self::faucet_manager_role()),
            (Self::deregister_faucet_root(), Self::faucet_manager_role()),
            (Self::update_ger_root(), Self::ger_injector_role()),
            (Self::remove_ger_root(), Self::ger_remover_role()),
        ])
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

    /// Storage slot name for the bridge's AggLayer network ID.
    ///
    /// Holds the network ID assigned to this bridge as a single felt in the first word element.
    /// It is set at account creation and never mutated by any bridge procedure.
    pub fn network_id_slot_name() -> &'static StorageSlotName {
        &NETWORK_ID_SLOT_NAME
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

    /// Returns every input-note script root a newly deployed AggLayer bridge account accepts.
    ///
    /// Any transaction consuming a note outside the account's allowlist is rejected wholesale by
    /// the auth procedure, so nothing it creates is ever committed, and the bridge's deployed fee
    /// policy must schedule a fee for every root in it.
    ///
    /// Besides the agglayer-specific notes, the bridge opts into three standards notes: the
    /// [`PauseConfigNote`], so the `ADMIN` role can toggle the emergency pause, the
    /// role-management [`RbacConfigNote`], which makes the bridge's RBAC role graph mutable
    /// on-chain (see the [`RbacConfigNote`] security considerations and the Administration
    /// section of `SPEC.md` for the associated caveats), and the
    /// [`ConstantFeePolicyConfigNote`], so the `ADMIN` role can reprice the bridge's fee
    /// schedule after deployment. On top of those, the set includes the configuration and
    /// sponsorship notes that [`AuthNetworkAccount`] adds to every standard network account.
    ///
    /// This is the deployment-time allowlist: an `ADMIN`-authored `NETWORK_ACCOUNT_CONFIG` note
    /// can add or remove entries later, so read a live account's allowlist via
    /// [`NetworkAccount::allowed_notes`](miden_standards::account::auth::NetworkAccount::allowed_notes).
    ///
    /// [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount
    pub fn allowed_notes() -> BTreeSet<NoteScriptRoot> {
        let mut notes = BTreeSet::from([
            ClaimNote::script_root(),
            B2AggNote::script_root(),
            ConfigAggBridgeNote::script_root(),
            DeregisterAggFaucetNote::script_root(),
            UpdateGerNote::script_root(),
            RemoveGerNote::script_root(),
            PauseConfigNote::script_root(),
            RbacConfigNote::script_root(),
            ConstantFeePolicyConfigNote::script_root(),
        ]);
        // The defaults every standard network account accepts (NETWORK_ACCOUNT_CONFIG and
        // FEE_SPONSORSHIP); `AuthNetworkAccount::new` adds them to whatever set it is given, so
        // including them here keeps this accessor equal to the deployed allowlist.
        notes.extend(AuthNetworkAccount::default_allowed_note_scripts());
        notes
    }

    // PAUSE NOTE
    // --------------------------------------------------------------------------------------------

    /// Builds a [`PauseConfigNote`] that toggles the emergency pause of the bridge account
    /// `bridge_id`. `sender` must hold the bridge's `ADMIN` role.
    ///
    /// Use this instead of [`PauseConfigNote::builder`] directly: it reports a non-public
    /// `bridge_id` as [`AgglayerBridgeError::NonPublicPauseNoteTarget`] rather than as an opaque
    /// note creation failure.
    ///
    /// # Errors
    /// Returns an error if `bridge_id` is not a public account, or if note creation fails.
    pub fn pause_note<R: FeltRng>(
        config: PauseConfig,
        sender: AccountId,
        bridge_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, AgglayerBridgeError> {
        let attachment = NetworkAccountTarget::new(bridge_id, NoteExecutionHint::Always)
            .map_err(AgglayerBridgeError::NonPublicPauseNoteTarget)?;

        PauseConfigNote::builder()
            .sender(sender)
            .target(bridge_id)
            .config(config)
            .attachment(attachment)
            .generate_serial_number(rng)
            .build()
            .map(Into::into)
            .map_err(AgglayerBridgeError::PauseNoteCreationFailed)
    }
}

impl From<AggLayerBridge> for AccountComponent {
    fn from(bridge: AggLayerBridge) -> Self {
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
            StorageSlot::with_value(
                NETWORK_ID_SLOT_NAME.clone(),
                Word::new([Felt::from(bridge.network_id), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            ),
        ];
        bridge_component(bridge_storage_slots)
    }
}

// TESTING
// ================================================================================================

#[cfg(any(feature = "testing", test))]
impl AggLayerBridge {
    const REGISTERED_GER_MAP_VALUE: Word = Word::new([
        miden_protocol::Felt::ONE,
        miden_protocol::Felt::ZERO,
        miden_protocol::Felt::ZERO,
        miden_protocol::Felt::ZERO,
    ]);

    /// Returns a boolean indicating whether the provided GER is present in storage of the provided
    /// bridge account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn is_ger_registered(
        ger: ExitRoot,
        bridge_account: &miden_protocol::account::Account,
    ) -> Result<bool, AgglayerBridgeError> {
        use miden_protocol::account::StorageMapKey;
        use miden_protocol::crypto::hash::poseidon2::Poseidon2;

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
    pub fn read_local_exit_root(
        account: &miden_protocol::account::Account,
    ) -> Result<Vec<miden_core::Felt>, AgglayerBridgeError> {
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

    /// Returns the AggLayer network ID stored in the bridge account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn network_id(
        account: &miden_protocol::account::Account,
    ) -> Result<u32, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(account)?;

        let value = account
            .storage()
            .get_item(AggLayerBridge::network_id_slot_name())
            .expect("should be able to read the network ID");
        let network_id = u32::try_from(value.to_vec()[0].as_canonical_u64())
            .map_err(|_| AgglayerBridgeError::InvalidNetworkId)?;

        Ok(network_id)
    }

    /// Returns the number of leaves in the Local Exit Tree (LET) frontier.
    pub fn read_let_num_leaves(account: &miden_protocol::account::Account) -> u64 {
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
    pub fn cgi_chain_hash(
        bridge_account: &miden_protocol::account::Account,
    ) -> Result<crate::claim_note::CgiChainHash, AgglayerBridgeError> {
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

        Ok(crate::claim_note::CgiChainHash::new(Self::chain_hash_bytes(
            cgi_chain_hash_lo,
            cgi_chain_hash_hi,
        )))
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
        bridge_account: &miden_protocol::account::Account,
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
    fn assert_bridge_account(
        account: &miden_protocol::account::Account,
    ) -> Result<(), AgglayerBridgeError> {
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
    fn assert_storage_slots(
        account: &miden_protocol::account::Account,
    ) -> Result<(), AgglayerBridgeError> {
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
    fn assert_code_commitment(
        account: &miden_protocol::account::Account,
    ) -> Result<(), AgglayerBridgeError> {
        if BRIDGE_CODE_COMMITMENT != account.code().commitment() {
            return Err(AgglayerBridgeError::CodeCommitmentMismatch);
        }

        Ok(())
    }

    /// Returns a vector of all storage slot names a bridge account must have.
    ///
    /// Besides the [`AggLayerBridge`] component's own slots, this includes the standards-owned
    /// `is_paused` slot: `pausable::assert_not_paused` treats a missing slot as unpaused, so this
    /// testing-side validator certifies the slot exists. (In production the slot is guaranteed by
    /// `AggLayerBridge::account_builder` always installing the `Pausable` component.)
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
            &*NETWORK_ID_SLOT_NAME,
            PausableStorage::is_paused_slot(),
        ]
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
    #[error("bridge role {0} must have at least one initial holder")]
    EmptyBridgeRole(RoleSymbol),
    #[error("the network ID stored in the bridge account does not fit into a u32")]
    InvalidNetworkId,
    #[error("bridge account must be public to be named by a network account target")]
    NonPublicPauseNoteTarget(#[source] NetworkAccountTargetError),
    #[error("failed to create a PAUSE_CONFIG note for the bridge account")]
    PauseNoteCreationFailed(#[source] NoteError),
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates an AggLayer Bridge component with the specified storage slots.
fn bridge_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let package = agglayer_bridge_component_package();
    let metadata = AccountComponentMetadata::new("agglayer::bridge")
        .with_description("Bridge component for AggLayer");

    AccountComponent::new(package, storage_slots, metadata)
        .expect("bridge component should satisfy the requirements of a valid account component")
}
