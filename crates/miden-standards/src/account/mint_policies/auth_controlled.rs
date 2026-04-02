use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlot, StorageSlotName};

use super::MintPolicyAuthority;
use crate::account::components::auth_controlled_library;
use crate::account::policy_manager::auth_controlled_initial_storage_slots;
use crate::procedure_digest;

// MINT POLICY AUTH CONTROLLED
// ================================================================================================

// Initialize the digest of the `allow_all` procedure of the mint auth-controlled policy component
// only once.
procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    MintAuthControlled::NAME,
    MintAuthControlled::ALLOW_ALL_PROC_NAME,
    auth_controlled_library
);

/// Initial policy configuration for the [`MintAuthControlled`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintAuthControlledConfig {
    /// Sets the initial policy to `allow_all`.
    #[default]
    AllowAll,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

/// An [`AccountComponent`] providing configurable mint-policy management for network faucets.
///
/// It reexports policy procedures from `miden::standards::mint_policies` and manager procedures
/// from `miden::standards::mint_policies::policy_manager`:
/// - `allow_all`
/// - `set_mint_policy`
/// - `get_mint_policy`
///
/// ## Storage Layout
///
/// - [`Self::active_policy_proc_root_slot`]: Procedure root of the active mint policy.
/// - [`Self::allowed_policy_proc_roots_slot`]: Set of allowed mint policy procedure roots.
/// - [`Self::policy_authority_slot`]: Policy authority mode
///   ([`MintPolicyAuthority::AuthControlled`] = tx auth, [`MintPolicyAuthority::OwnerControlled`] =
///   external owner).
#[derive(Debug, Clone, Copy)]
pub struct MintAuthControlled {
    pub(crate) initial_policy_root: Word,
}

impl MintAuthControlled {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::mint_policies::auth_controlled";

    const ALLOW_ALL_PROC_NAME: &str = "allow_all";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`MintAuthControlled`] component from the provided configuration.
    pub fn new(policy: MintAuthControlledConfig) -> Self {
        let initial_policy_root = match policy {
            MintAuthControlledConfig::AllowAll => Self::allow_all_policy_root(),
            MintAuthControlledConfig::CustomInitialRoot(root) => root,
        };

        Self { initial_policy_root }
    }

    /// Creates a new [`MintAuthControlled`] component with `allow_all` policy as
    /// default.
    pub fn allow_all() -> Self {
        Self::new(MintAuthControlledConfig::AllowAll)
    }

    /// Returns the [`StorageSlotName`] where the active mint policy procedure root is stored.
    pub fn active_policy_proc_root_slot() -> &'static StorageSlotName {
        super::active_policy_proc_root_slot_name()
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policy_proc_roots_slot() -> &'static StorageSlotName {
        super::allowed_policy_proc_roots_slot_name()
    }

    /// Returns the storage slot schema for the active mint policy root.
    pub fn active_policy_proc_root_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        super::active_policy_proc_root_slot_schema()
    }

    /// Returns the storage slot schema for the allowed policy roots map.
    pub fn allowed_policy_proc_roots_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        super::allowed_policy_proc_roots_slot_schema()
    }

    /// Returns the [`StorageSlotName`] containing policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        MintPolicyAuthority::slot()
    }

    /// Returns the storage slot schema for policy authority mode.
    pub fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        super::policy_authority_slot_schema()
    }

    /// Policy authority slot with this component's fixed mode
    /// ([`MintPolicyAuthority::AuthControlled`]).
    pub fn policy_authority_value_slot() -> StorageSlot {
        StorageSlot::from(MintPolicyAuthority::AuthControlled)
    }

    /// Returns the default `allow_all` policy procedure root (MAST digest).
    pub fn allow_all_policy_root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }

    /// Returns the policy authority used by this component.
    pub fn mint_policy_authority(&self) -> MintPolicyAuthority {
        MintPolicyAuthority::AuthControlled
    }
}

impl Default for MintAuthControlled {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl From<MintAuthControlled> for AccountComponent {
    fn from(auth_controlled: MintAuthControlled) -> Self {
        let slots = auth_controlled_initial_storage_slots(
            auth_controlled.initial_policy_root,
            MintAuthControlled::active_policy_proc_root_slot(),
            MintAuthControlled::allowed_policy_proc_roots_slot(),
            MintAuthControlled::policy_authority_value_slot(),
            MintAuthControlled::allow_all_policy_root(),
        );

        let storage_schema = StorageSchema::new(vec![
            MintAuthControlled::active_policy_proc_root_slot_schema(),
            MintAuthControlled::allowed_policy_proc_roots_slot_schema(),
            MintAuthControlled::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata =
            AccountComponentMetadata::new(MintAuthControlled::NAME, [AccountType::FungibleFaucet])
                .with_description(
                    "Mint policy auth controlled component for network fungible faucets",
                )
                .with_storage_schema(storage_schema);

        AccountComponent::new(auth_controlled_library(), slots, metadata).expect(
            "mint policy auth controlled component should satisfy the requirements of a valid account component",
        )
    }
}
