extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, FieldElement, ONE, Word, ZERO};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountComponent, AccountId, StorageSlot, StorageSlotName};
use miden_protocol::crypto::hash::rpo::Rpo256;
use miden_utils_sync::LazyLock;
use thiserror::Error;

use super::agglayer_bridge_component_library;
use crate::claim_note::Keccak256Output;
pub use crate::{
    B2AggNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    EthAddressFormat,
    EthAmount,
    EthAmountError,
    ExitRoot,
    GlobalIndex,
    GlobalIndexError,
    LeafData,
    MetadataHash,
    ProofData,
    SmtNode,
    UpdateGerNote,
    create_claim_note,
};

// CONSTANTS
// ================================================================================================
// Include the generated agglayer constants
include!(concat!(env!("OUT_DIR"), "/agglayer_constants.rs"));

// AGGLAYER BRIDGE STRUCT
// ================================================================================================

static GER_MAP_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::ger")
        .expect("bridge storage slot name should be valid")
});
static LET_FRONTIER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let").expect("LET storage slot name should be valid")
});
static LET_ROOT_LO_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let::root_lo")
        .expect("LET root_lo storage slot name should be valid")
});
static LET_ROOT_HI_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let::root_hi")
        .expect("LET root_hi storage slot name should be valid")
});
static LET_NUM_LEAVES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::let::num_leaves")
        .expect("LET num_leaves storage slot name should be valid")
});
static FAUCET_REGISTRY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::faucet_registry")
        .expect("faucet registry storage slot name should be valid")
});
static TOKEN_REGISTRY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::token_registry")
        .expect("token registry storage slot name should be valid")
});
static BRIDGE_ADMIN_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::admin")
        .expect("bridge admin storage slot name should be valid")
});
static GER_MANAGER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::ger_manager")
        .expect("GER manager storage slot name should be valid")
});
static CGI_CHAIN_HASH_LO_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::cgi_chain_hash_lo")
        .expect("CGI chain hash lo storage slot name should be valid")
});
static CGI_CHAIN_HASH_HI_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::cgi_chain_hash_hi")
        .expect("CGI chain hash hi storage slot name should be valid")
});
static CLAIM_NULLIFIERS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::bridge::claim_nullifiers")
        .expect("claim nullifiers storage slot name should be valid")
});

/// An [`AccountComponent`] implementing the AggLayer Bridge.
///
/// It reexports the procedures from `miden::agglayer::bridge`. When linking against this
/// component, the `agglayer` library must be available to the assembler.
/// The procedures of this component are:
/// - `register_faucet`, which registers a faucet in the bridge.
/// - `update_ger`, which injects a new GER into the storage map.
/// - `bridge_out`, which bridges an asset out of Miden to the destination network.
/// - `claim`, which validates a claim against the AggLayer bridge and creates a MINT note for the
///   AggFaucet.
///
/// ## Storage Layout
///
/// - [`Self::ger_map_slot_name`]: Stores the GERs.
/// - [`Self::let_frontier_slot_name`]: Stores the Local Exit Tree (LET) frontier.
/// - [`Self::ler_lo_slot_name`]: Stores the lower 32 bits of the LET root.
/// - [`Self::ler_hi_slot_name`]: Stores the upper 32 bits of the LET root.
/// - [`Self::let_num_leaves_slot_name`]: Stores the number of leaves in the LET frontier.
/// - [`Self::faucet_registry_slot_name`]: Stores the faucet registry map.
/// - [`Self::token_registry_slot_name`]: Stores the token address → faucet ID map.
/// - [`Self::bridge_admin_slot_name`]: Stores the bridge admin account ID.
/// - [`Self::ger_manager_slot_name`]: Stores the GER manager account ID.
/// - [`Self::cgi_lo_slot_name`]: Stores the lower 128 bits of the CGI chain hash.
/// - [`Self::cgi_hi_slot_name`]: Stores the upper 128 bits of the CGI chain hash.
/// - [`Self::claim_nullifiers_slot_name`]: Stores the CLAIM note nullifiers map (RPO(leaf_index,
///   source_bridge_network) → \[1, 0, 0, 0\]).
///
/// The bridge starts with an empty faucet registry; faucets are registered at runtime via
/// CONFIG_AGG_BRIDGE notes.
#[derive(Debug, Clone)]
pub struct AggLayerBridge {
    bridge_admin_id: AccountId,
    ger_manager_id: AccountId,
}

impl AggLayerBridge {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    const REGISTERED_GER_MAP_VALUE: Word = Word::new([ONE, ZERO, ZERO, ZERO]);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new AggLayer bridge component with the standard configuration.
    pub fn new(bridge_admin_id: AccountId, ger_manager_id: AccountId) -> Self {
        Self { bridge_admin_id, ger_manager_id }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Storage slot name for the GERs map.
    pub fn ger_map_slot_name() -> &'static StorageSlotName {
        &GER_MAP_SLOT_NAME
    }

    /// Storage slot name for the Local Exit Tree (LET) frontier.
    pub fn let_frontier_slot_name() -> &'static StorageSlotName {
        &LET_FRONTIER_SLOT_NAME
    }

    /// Storage slot name for the lower 32 bits of the LET root.
    pub fn ler_lo_slot_name() -> &'static StorageSlotName {
        &LET_ROOT_LO_SLOT_NAME
    }

    /// Storage slot name for the upper 32 bits of the LET root.
    pub fn ler_hi_slot_name() -> &'static StorageSlotName {
        &LET_ROOT_HI_SLOT_NAME
    }

    /// Storage slot name for the number of leaves in the LET frontier.
    pub fn let_num_leaves_slot_name() -> &'static StorageSlotName {
        &LET_NUM_LEAVES_SLOT_NAME
    }

    /// Storage slot name for the faucet registry map.
    pub fn faucet_registry_slot_name() -> &'static StorageSlotName {
        &FAUCET_REGISTRY_SLOT_NAME
    }

    /// Storage slot name for the token registry map.
    pub fn token_registry_slot_name() -> &'static StorageSlotName {
        &TOKEN_REGISTRY_SLOT_NAME
    }

    /// Storage slot name for the bridge admin account ID.
    pub fn bridge_admin_slot_name() -> &'static StorageSlotName {
        &BRIDGE_ADMIN_SLOT_NAME
    }

    /// Storage slot name for the GER manager account ID.
    pub fn ger_manager_slot_name() -> &'static StorageSlotName {
        &GER_MANAGER_SLOT_NAME
    }

    /// Storage slot name for the lower 128 bits of the CGI chain hash.
    pub fn cgi_lo_slot_name() -> &'static StorageSlotName {
        &CGI_CHAIN_HASH_LO_SLOT_NAME
    }

    /// Storage slot name for the upper 128 bits of the CGI chain hash.
    pub fn cgi_hi_slot_name() -> &'static StorageSlotName {
        &CGI_CHAIN_HASH_HI_SLOT_NAME
    }

    /// Storage slot name for the CLAIM note nullifiers map.
    pub fn claim_nullifiers_slot_name() -> &'static StorageSlotName {
        &CLAIM_NULLIFIERS_SLOT_NAME
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
        bridge_account: Account,
    ) -> Result<bool, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(&bridge_account)?;

        // Compute the expected GER hash: rpo256::merge(GER_UPPER, GER_LOWER)
        let mut ger_lower: [Felt; 4] = ger.to_elements()[0..4].try_into().unwrap();
        let mut ger_upper: [Felt; 4] = ger.to_elements()[4..8].try_into().unwrap();
        // Elements are reversed: rpo256::merge treats stack as if loaded BE from memory
        // The following will produce matching hashes:
        // Rust
        // Hasher::merge(&[a, b, c, d], &[e, f, g, h])
        // MASM
        // rpo256::merge(h, g, f, e, d, c, b, a)
        ger_lower.reverse();
        ger_upper.reverse();
        let ger_hash = Rpo256::merge(&[ger_upper.into(), ger_lower.into()]);

        // Get the value stored by the GER hash. If this GER was registered, the value would be
        // equal to [1, 0, 0, 0]
        let stored_value = bridge_account
            .storage()
            .get_map_item(AggLayerBridge::ger_map_slot_name(), ger_hash)
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
    /// - [`AggLayerBridge::ler_lo_slot_name`] — low word of the root
    /// - [`AggLayerBridge::ler_hi_slot_name`] — high word of the root
    ///
    /// Returns the 256-bit root as 8 `Felt`s: first the 4 elements of `root_lo` (in
    /// reverse of their storage order), followed by the 4 elements of `root_hi` (also in
    /// reverse of their storage order). For an empty/uninitialized tree, all elements are
    /// zeros.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn read_local_exit_root(account: &Account) -> Result<Vec<Felt>, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(account)?;

        let root_lo_slot = AggLayerBridge::ler_lo_slot_name();
        let root_hi_slot = AggLayerBridge::ler_hi_slot_name();

        let root_lo = account
            .storage()
            .get_item(root_lo_slot)
            .expect("should be able to read LET root lo");
        let root_hi = account
            .storage()
            .get_item(root_hi_slot)
            .expect("should be able to read LET root hi");

        let mut root = Vec::with_capacity(8);
        root.extend(root_lo.to_vec().into_iter().rev());
        root.extend(root_hi.to_vec().into_iter().rev());

        Ok(root)
    }

    /// Returns the number of leaves in the Local Exit Tree (LET) frontier.
    pub fn read_let_num_leaves(account: &Account) -> u64 {
        let num_leaves_slot = AggLayerBridge::let_num_leaves_slot_name();
        let value = account
            .storage()
            .get_item(num_leaves_slot)
            .expect("should be able to read LET num leaves");
        value.to_vec()[0].as_int()
    }

    /// Returns the claimed global index (CGI) chain hash from the corresponding storage slot.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerBridge`] account.
    pub fn cgi_chain_hash(
        bridge_account: &Account,
    ) -> Result<Keccak256Output, AgglayerBridgeError> {
        // check that the provided account is a bridge account
        Self::assert_bridge_account(bridge_account)?;

        let cgi_chain_hash_lo = bridge_account
            .storage()
            .get_item(AggLayerBridge::cgi_lo_slot_name())
            .expect("failed to get CGI hash chain lo slot");
        let cgi_chain_hash_hi = bridge_account
            .storage()
            .get_item(AggLayerBridge::cgi_hi_slot_name())
            .expect("failed to get CGI hash chain hi slot");

        let cgi_chain_hash_bytes = cgi_chain_hash_lo
            .iter()
            .rev()
            .chain(cgi_chain_hash_hi.iter().rev())
            .flat_map(|felt| (felt.as_int() as u32).to_le_bytes())
            .collect::<Vec<u8>>();

        Ok(Keccak256Output::new(
            cgi_chain_hash_bytes
                .try_into()
                .expect("keccak hash should consist of exactly 32 bytes"),
        ))
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

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
            &*FAUCET_REGISTRY_SLOT_NAME,
            &*TOKEN_REGISTRY_SLOT_NAME,
            &*BRIDGE_ADMIN_SLOT_NAME,
            &*GER_MANAGER_SLOT_NAME,
            &*CGI_CHAIN_HASH_LO_SLOT_NAME,
            &*CGI_CHAIN_HASH_HI_SLOT_NAME,
            &*CLAIM_NULLIFIERS_SLOT_NAME,
        ]
    }
}

impl From<AggLayerBridge> for AccountComponent {
    fn from(bridge: AggLayerBridge) -> Self {
        let bridge_admin_word = Word::new([
            Felt::ZERO,
            Felt::ZERO,
            bridge.bridge_admin_id.suffix(),
            bridge.bridge_admin_id.prefix().as_felt(),
        ]);
        let ger_manager_word = Word::new([
            Felt::ZERO,
            Felt::ZERO,
            bridge.ger_manager_id.suffix(),
            bridge.ger_manager_id.prefix().as_felt(),
        ]);

        let bridge_storage_slots = vec![
            StorageSlot::with_empty_map(GER_MAP_SLOT_NAME.clone()),
            StorageSlot::with_empty_map(LET_FRONTIER_SLOT_NAME.clone()),
            StorageSlot::with_value(LET_ROOT_LO_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(LET_ROOT_HI_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_value(LET_NUM_LEAVES_SLOT_NAME.clone(), Word::empty()),
            StorageSlot::with_empty_map(FAUCET_REGISTRY_SLOT_NAME.clone()),
            StorageSlot::with_empty_map(TOKEN_REGISTRY_SLOT_NAME.clone()),
            StorageSlot::with_value(BRIDGE_ADMIN_SLOT_NAME.clone(), bridge_admin_word),
            StorageSlot::with_value(GER_MANAGER_SLOT_NAME.clone(), ger_manager_word),
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

/// Creates an AggLayer Bridge component with the specified storage slots.
fn bridge_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_bridge_component_library();
    let metadata = AccountComponentMetadata::new("agglayer::bridge")
        .with_description("Bridge component for AggLayer")
        .with_supports_all_types();

    AccountComponent::new(library, storage_slots, metadata)
        .expect("bridge component should satisfy the requirements of a valid account component")
}
