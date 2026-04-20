use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};

use super::{BurnAuthControlled, BurnPolicyAuthority};
use crate::account::components::burn_owner_controlled_library;
use crate::procedure_digest;

// BURN POLICY OWNER CONTROLLED
// ================================================================================================

// Initialize the digest of the `owner_only` procedure of the burn owner-controlled policy component
// only once.
procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    BurnOwnerControlled::NAME,
    BurnOwnerControlled::OWNER_ONLY_PROC_NAME,
    burn_owner_controlled_library
);

/// Initial policy configuration for the [`BurnOwnerControlled`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum BurnOwnerControlledConfig {
    /// Sets the initial policy to `allow_all`.
    #[default]
    AllowAll,
    /// Sets the initial policy to `owner_only`.
    OwnerOnly,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

/// An [`AccountComponent`] providing configurable burn-policy management for fungible faucets.
///
/// It reexports policy procedures from `miden::standards::burn_policies` and manager procedures
/// from `miden::standards::burn_policies::policy_manager`:
/// - `allow_all`
/// - `owner_only`
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
pub struct BurnOwnerControlled {
    initial_policy_root: Word,
}

impl BurnOwnerControlled {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::burn_policies::owner_controlled";

    const OWNER_ONLY_PROC_NAME: &str = "owner_only";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BurnOwnerControlled`] component from the provided configuration.
    pub fn new(policy: BurnOwnerControlledConfig) -> Self {
        let initial_policy_root = match policy {
            BurnOwnerControlledConfig::AllowAll => Self::allow_all_policy_root(),
            BurnOwnerControlledConfig::OwnerOnly => Self::owner_only_policy_root(),
            BurnOwnerControlledConfig::CustomInitialRoot(root) => root,
        };

        Self { initial_policy_root }
    }

    /// Creates a new [`BurnOwnerControlled`] component with `allow_all` policy as default.
    pub fn allow_all() -> Self {
        Self::new(BurnOwnerControlledConfig::AllowAll)
    }

    /// Creates a new [`BurnOwnerControlled`] component with owner-only policy.
    pub fn owner_only() -> Self {
        Self::new(BurnOwnerControlledConfig::OwnerOnly)
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
    /// ([`BurnPolicyAuthority::OwnerControlled`]).
    pub fn policy_authority_value_slot() -> StorageSlot {
        StorageSlot::from(BurnPolicyAuthority::OwnerControlled)
    }

    /// Returns the default `allow_all` policy procedure root (MAST digest).
    pub fn allow_all_policy_root() -> Word {
        BurnAuthControlled::allow_all_policy_root()
    }

    /// Returns the default `owner_only` policy procedure root (MAST digest).
    pub fn owner_only_policy_root() -> Word {
        *OWNER_ONLY_POLICY_ROOT
    }

    /// Returns the policy authority used by this component.
    pub fn burn_policy_authority(&self) -> BurnPolicyAuthority {
        BurnPolicyAuthority::OwnerControlled
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            BurnOwnerControlled::active_policy_proc_root_slot_schema(),
            BurnOwnerControlled::allowed_policy_proc_roots_slot_schema(),
            BurnOwnerControlled::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(BurnOwnerControlled::NAME, [AccountType::FungibleFaucet])
            .with_description("Burn policy owner controlled component for fungible faucets")
            .with_storage_schema(storage_schema)
    }

    fn initial_storage_slots(&self) -> Vec<StorageSlot> {
        let initial_policy_root = self.initial_policy_root;
        let allow_all_procedure_root = Self::allow_all_policy_root();
        let owner_only_procedure_root = Self::owner_only_policy_root();
        let allowed_policy_flag = Word::from([1u32, 0, 0, 0]);
        let mut allowed_policy_entries = vec![
            (StorageMapKey::from_raw(allow_all_procedure_root), allowed_policy_flag),
            (StorageMapKey::from_raw(owner_only_procedure_root), allowed_policy_flag),
        ];

        if initial_policy_root != allow_all_procedure_root
            && initial_policy_root != owner_only_procedure_root
        {
            allowed_policy_entries
                .push((StorageMapKey::from_raw(initial_policy_root), allowed_policy_flag));
        }

        let allowed_policy_proc_roots = StorageMap::with_entries(allowed_policy_entries)
            .expect("allowed burn policy roots should have unique keys");

        vec![
            StorageSlot::with_value(
                Self::active_policy_proc_root_slot().clone(),
                initial_policy_root,
            ),
            StorageSlot::with_map(
                Self::allowed_policy_proc_roots_slot().clone(),
                allowed_policy_proc_roots,
            ),
            Self::policy_authority_value_slot(),
        ]
    }
}

impl Default for BurnOwnerControlled {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl From<BurnOwnerControlled> for AccountComponent {
    fn from(burn_owner_controlled: BurnOwnerControlled) -> Self {
        let slots = burn_owner_controlled.initial_storage_slots();

        let metadata = BurnOwnerControlled::component_metadata();

        AccountComponent::new(burn_owner_controlled_library(), slots, metadata).expect(
            "burn policy owner controlled component should satisfy the requirements of a valid account component",
        )
    }
}
