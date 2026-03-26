use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, AccountType, StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

use super::{BurnAuthControlled, BurnPolicyAuthority};
use crate::account::components::burn_owner_controlled_library;
use crate::account::policy_manager::OwnerControlled;
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

static ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});
static ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});

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
pub struct BurnOwnerControlled(OwnerControlled);

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

        Self(OwnerControlled { initial_policy_root })
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
        &ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policy_proc_roots_slot() -> &'static StorageSlotName {
        &ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the storage slot schema for the active burn policy root.
    pub fn active_policy_proc_root_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::active_policy_proc_root_slot().clone(),
            StorageSlotSchema::value(
                "The procedure root of the active burn policy in the burn policy owner controlled component",
                [
                    FeltSchema::felt("proc_root_0"),
                    FeltSchema::felt("proc_root_1"),
                    FeltSchema::felt("proc_root_2"),
                    FeltSchema::felt("proc_root_3"),
                ],
            ),
        )
    }

    /// Returns the storage slot schema for the allowed policy roots map.
    pub fn allowed_policy_proc_roots_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::allowed_policy_proc_roots_slot().clone(),
            StorageSlotSchema::map(
                "The set of allowed burn policy procedure roots in the burn policy owner controlled component",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`StorageSlotName`] containing policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        BurnPolicyAuthority::slot()
    }

    /// Returns the storage slot schema for policy authority mode.
    pub fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::policy_authority_slot().clone(),
            StorageSlotSchema::value(
                "Policy authority mode (AuthControlled = tx auth, OwnerControlled = external owner)",
                [
                    FeltSchema::u8("policy_authority"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    /// Policy authority slot with this component's fixed mode
    /// ([`BurnPolicyAuthority::OwnerControlled`]).
    pub fn policy_authority_value_slot() -> StorageSlot {
        StorageSlot::from(BurnPolicyAuthority::OwnerControlled)
    }

    /// Returns the default allow-all policy root.
    pub fn allow_all_policy_root() -> Word {
        BurnAuthControlled::allow_all_policy_root()
    }

    /// Returns the default owner-only policy root.
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
}

impl Default for BurnOwnerControlled {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl From<BurnOwnerControlled> for AccountComponent {
    fn from(burn_owner_controlled: BurnOwnerControlled) -> Self {
        let slots = burn_owner_controlled.0.burn_initial_storage_slots(
            BurnOwnerControlled::active_policy_proc_root_slot(),
            BurnOwnerControlled::allowed_policy_proc_roots_slot(),
            BurnOwnerControlled::policy_authority_value_slot(),
            BurnOwnerControlled::allow_all_policy_root(),
            BurnOwnerControlled::owner_only_policy_root(),
        );

        let metadata = BurnOwnerControlled::component_metadata();

        AccountComponent::new(burn_owner_controlled_library(), slots, metadata).expect(
            "burn policy owner controlled component should satisfy the requirements of a valid account component",
        )
    }
}
