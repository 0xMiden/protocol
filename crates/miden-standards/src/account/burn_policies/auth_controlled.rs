use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlot, StorageSlotName};

use super::BurnPolicyAuthority;
use crate::account::components::burn_auth_controlled_library;
use crate::account::policy_manager::auth_controlled_initial_storage_slots;
use crate::procedure_digest;

// BURN POLICY AUTH CONTROLLED
// ================================================================================================

// Initialize the digest of the `allow_all` procedure of the burn auth-controlled policy component
// only once.
procedure_digest!(
    ALLOW_ALL_POLICY_ROOT,
    BurnAuthControlled::NAME,
    BurnAuthControlled::ALLOW_ALL_PROC_NAME,
    burn_auth_controlled_library
);

/// Initial policy configuration for the [`BurnAuthControlled`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum BurnAuthControlledConfig {
    /// Sets the initial policy to `allow_all`.
    #[default]
    AllowAll,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

/// An [`AccountComponent`] providing configurable burn-policy management for fungible faucets.
///
/// It reexports policy procedures from `miden::standards::burn_policies` and manager procedures
/// from `miden::standards::burn_policies::policy_manager`:
/// - `allow_all`
/// - `set_burn_policy`
/// - `get_burn_policy`
///
/// ## Storage Layout
///
/// - [`Self::active_policy_proc_root_slot`]: Procedure root of the active burn policy.
/// - [`Self::allowed_policy_proc_roots_slot`]: Set of allowed burn policy procedure roots.
/// - [`Self::policy_authority_slot`]: Policy authority mode
///   ([`BurnPolicyAuthority::AuthControlled`] = tx auth, [`BurnPolicyAuthority::OwnerControlled`] =
///   external owner).
#[derive(Debug, Clone, Copy)]
pub struct BurnAuthControlled {
    pub(crate) initial_policy_root: Word,
}

impl BurnAuthControlled {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::burn_policies::auth_controlled";

    const ALLOW_ALL_PROC_NAME: &str = "allow_all";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BurnAuthControlled`] component from the provided configuration.
    pub fn new(policy: BurnAuthControlledConfig) -> Self {
        let initial_policy_root = match policy {
            BurnAuthControlledConfig::AllowAll => Self::allow_all_policy_root(),
            BurnAuthControlledConfig::CustomInitialRoot(root) => root,
        };

        Self { initial_policy_root }
    }

    /// Creates a new [`BurnAuthControlled`] component with `allow_all` policy.
    pub fn allow_all() -> Self {
        Self::new(BurnAuthControlledConfig::AllowAll)
    }

    /// Returns the [`StorageSlotName`] where the active burn policy procedure root is stored.
    pub fn active_policy_proc_root_slot() -> &'static StorageSlotName {
        super::active_policy_proc_root_slot_name()
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policy_proc_roots_slot() -> &'static StorageSlotName {
        super::allowed_policy_proc_roots_slot_name()
    }

    /// Returns the storage slot schema for the active burn policy root.
    pub fn active_policy_proc_root_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        super::active_policy_proc_root_slot_schema()
    }

    /// Returns the storage slot schema for the allowed policy roots map.
    pub fn allowed_policy_proc_roots_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        super::allowed_policy_proc_roots_slot_schema()
    }

    /// Returns the [`StorageSlotName`] containing policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        BurnPolicyAuthority::slot()
    }

    /// Returns the storage slot schema for policy authority mode.
    pub fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        super::policy_authority_slot_schema()
    }

    /// Policy authority slot with this component's fixed mode
    /// ([`BurnPolicyAuthority::AuthControlled`]).
    pub fn policy_authority_value_slot() -> StorageSlot {
        StorageSlot::from(BurnPolicyAuthority::AuthControlled)
    }

    /// Returns the default `allow_all` policy procedure root (MAST digest).
    pub fn allow_all_policy_root() -> Word {
        *ALLOW_ALL_POLICY_ROOT
    }

    /// Returns the policy authority used by this component.
    pub fn burn_policy_authority(&self) -> BurnPolicyAuthority {
        BurnPolicyAuthority::AuthControlled
    }
}

impl Default for BurnAuthControlled {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl From<BurnAuthControlled> for AccountComponent {
    fn from(auth_controlled: BurnAuthControlled) -> Self {
        let slots = auth_controlled_initial_storage_slots(
            auth_controlled.initial_policy_root,
            BurnAuthControlled::active_policy_proc_root_slot(),
            BurnAuthControlled::allowed_policy_proc_roots_slot(),
            BurnAuthControlled::policy_authority_value_slot(),
            BurnAuthControlled::allow_all_policy_root(),
        );

        let storage_schema = StorageSchema::new(vec![
            BurnAuthControlled::active_policy_proc_root_slot_schema(),
            BurnAuthControlled::allowed_policy_proc_roots_slot_schema(),
            BurnAuthControlled::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata =
            AccountComponentMetadata::new(BurnAuthControlled::NAME, [AccountType::FungibleFaucet])
                .with_description("Burn policy auth controlled component for fungible faucets")
                .with_storage_schema(storage_schema);

        AccountComponent::new(burn_auth_controlled_library(), slots, metadata).expect(
            "burn policy auth controlled component should satisfy the requirements of a valid account component",
        )
    }
}
