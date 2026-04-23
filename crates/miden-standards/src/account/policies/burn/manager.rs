use miden_protocol::account::StorageSlotName;
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use super::AllowAll;
use super::owner_controlled::{Config, OwnerOnly};
use crate::account::components::burn_policy_manager_library;
use crate::account::policies::{Burn, PolicyAuthority, PolicyKind, PolicyManager};

// STORAGE SLOT NAMES
// ================================================================================================

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

static ACTIVE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});

static ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});

// POLICY KIND IMPL
// ================================================================================================

impl PolicyKind for Burn {
    const COMPONENT_NAME: &'static str =
        "miden::standards::components::policies::burn::policy_manager";
    const COMPONENT_DESCRIPTION: &'static str = "Burn policy manager for fungible faucets";
    const ACTIVE_POLICY_DESC: &'static str = "Active burn policy procedure root";
    const ALLOWED_POLICIES_DESC: &'static str = "Allowed burn policy procedure roots";
    const AUTHORITY_DESC: &'static str = "Burn policy authority";
    const AUTHORITY_FELT_LABEL: &'static str = "burn_policy_authority";

    fn library() -> Library {
        burn_policy_manager_library()
    }

    fn active_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_POLICY_PROC_ROOT_SLOT_NAME
    }

    fn allowed_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME
    }

    fn policy_authority_slot() -> &'static StorageSlotName {
        &POLICY_AUTHORITY_SLOT_NAME
    }
}

// KIND-SPECIFIC CONSTRUCTORS
// ================================================================================================

impl PolicyManager<Burn> {
    /// Convenience: an auth-controlled burn policy manager with `allow_all` as the active (and only
    /// allowed) policy.
    pub fn auth_controlled() -> Self {
        Self::new(PolicyAuthority::AuthControlled, AllowAll::root())
    }

    /// Convenience: an owner-controlled burn policy manager. The active policy is chosen by
    /// `config`; both `allow_all` and `owner_only` are registered in the allowed-policies list so
    /// the owner can switch between them at runtime via `set_burn_policy`.
    pub fn owner_controlled(config: Config) -> Self {
        Self::new(PolicyAuthority::OwnerControlled, config.initial_policy_root())
            .with_allowed_policy(AllowAll::root())
            .with_allowed_policy(OwnerOnly::root())
    }
}
