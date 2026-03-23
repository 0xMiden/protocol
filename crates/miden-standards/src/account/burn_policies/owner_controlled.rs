use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
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
use miden_protocol::utils::sync::LazyLock;

use super::{AuthControlled, BurnPolicyAuthority};
use crate::account::components::burn_owner_controlled_library;
use crate::procedure_digest;

procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    OwnerControlled::NAME,
    OwnerControlled::OWNER_ONLY_PROC_NAME,
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
pub struct OwnerControlled {
    initial_policy_root: Word,
}

/// Initial policy configuration for the [`OwnerControlled`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum OwnerControlledInitConfig {
    /// Sets the initial policy to `allow_all`.
    #[default]
    AllowAll,
    /// Sets the initial policy to `owner_only`.
    OwnerOnly,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

impl OwnerControlled {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::burn_policies::owner_controlled";

    const OWNER_ONLY_PROC_NAME: &str = "owner_only";

    /// Creates a new [`OwnerControlled`] component from the provided configuration.
    pub fn new(policy: OwnerControlledInitConfig) -> Self {
        let initial_policy_root = match policy {
            OwnerControlledInitConfig::AllowAll => Self::allow_all_policy_root(),
            OwnerControlledInitConfig::OwnerOnly => Self::owner_only_policy_root(),
            OwnerControlledInitConfig::CustomInitialRoot(root) => root,
        };

        Self { initial_policy_root }
    }

    /// Creates a new [`OwnerControlled`] component with `allow_all` policy as default.
    pub fn allow_all() -> Self {
        Self::new(OwnerControlledInitConfig::AllowAll)
    }

    /// Creates a new [`OwnerControlled`] component with owner-only policy.
    pub fn owner_only() -> Self {
        Self::new(OwnerControlledInitConfig::OwnerOnly)
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

    /// Returns the default allow-all policy root.
    pub fn allow_all_policy_root() -> Word {
        AuthControlled::allow_all_policy_root()
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
            OwnerControlled::active_policy_proc_root_slot_schema(),
            OwnerControlled::allowed_policy_proc_roots_slot_schema(),
            OwnerControlled::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(OwnerControlled::NAME, [AccountType::FungibleFaucet])
            .with_description("Burn policy owner controlled component for fungible faucets")
            .with_storage_schema(storage_schema)
    }
}

impl Default for OwnerControlled {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl From<OwnerControlled> for AccountComponent {
    fn from(owner_controlled: OwnerControlled) -> Self {
        let active_policy_proc_root_slot = StorageSlot::with_value(
            OwnerControlled::active_policy_proc_root_slot().clone(),
            owner_controlled.initial_policy_root,
        );
        let allowed_policy_flag = Word::from([1u32, 0, 0, 0]);
        let allow_all_policy_root = OwnerControlled::allow_all_policy_root();
        let owner_only_policy_root = OwnerControlled::owner_only_policy_root();

        let mut allowed_policy_entries = vec![
            (StorageMapKey::from_raw(allow_all_policy_root), allowed_policy_flag),
            (StorageMapKey::from_raw(owner_only_policy_root), allowed_policy_flag),
        ];

        if owner_controlled.initial_policy_root != allow_all_policy_root
            && owner_controlled.initial_policy_root != owner_only_policy_root
        {
            allowed_policy_entries.push((
                StorageMapKey::from_raw(owner_controlled.initial_policy_root),
                allowed_policy_flag,
            ));
        }

        let allowed_policy_proc_roots = StorageMap::with_entries(allowed_policy_entries)
            .expect("allowed burn policy roots should have unique keys");

        let allowed_policy_proc_roots_slot = StorageSlot::with_map(
            OwnerControlled::allowed_policy_proc_roots_slot().clone(),
            allowed_policy_proc_roots,
        );
        let policy_authority_slot = StorageSlot::from(owner_controlled.burn_policy_authority());

        let metadata = OwnerControlled::component_metadata();

        AccountComponent::new(
            burn_owner_controlled_library(),
            vec![
                active_policy_proc_root_slot,
                allowed_policy_proc_roots_slot,
                policy_authority_slot,
            ],
            metadata,
        )
        .expect(
            "burn policy owner controlled component should satisfy the requirements of a valid account component",
        )
    }
}
