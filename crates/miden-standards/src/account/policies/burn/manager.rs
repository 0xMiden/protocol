use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, StorageSlotName};
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use super::{BurnAllowAll, BurnOwnerControlledConfig};
use crate::account::components::burn_policy_manager_library;
use crate::account::policies::PolicyAuthority;
use crate::account::policies::manager::{BurnPolicyKind, PolicyKind, PolicyManager};

// STORAGE SLOT NAMES
// ================================================================================================

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::burn::policy_manager::policy_authority",
    )
    .expect("storage slot name should be valid")
});

static ACTIVE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::burn::policy_manager::active_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

static ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::burn::policy_manager::allowed_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

// POLICY KIND IMPL
// ================================================================================================

impl PolicyKind for BurnPolicyKind {
    const COMPONENT_NAME: &'static str =
        "miden::standards::components::faucets::policies::burn::policy_manager";
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

// BURN POLICY MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the three policy-manager storage slots and the manager
/// procedures for the burn side.
///
/// Pair with at least one burn policy component (e.g. [`BurnAllowAll`], [`super::BurnOwnerOnly`])
/// whose procedure root is registered in this manager's allowed-policies map.
#[derive(Debug, Clone)]
pub struct BurnPolicyManager(PolicyManager<BurnPolicyKind>);

impl BurnPolicyManager {
    // KIND-SPECIFIC CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Convenience: an auth-controlled burn policy manager with `allow_all` as the active (and
    /// only allowed) policy.
    pub fn auth_controlled() -> Self {
        Self(PolicyManager::new(PolicyAuthority::AuthControlled, BurnAllowAll::root()))
    }

    /// Convenience: an owner-controlled burn policy manager. Only the policy chosen by `config`
    /// is registered as allowed; if you want to permit runtime switching to another policy,
    /// register it explicitly via [`Self::with_allowed_policy`] and add the corresponding policy
    /// component to the account.
    pub fn owner_controlled(config: BurnOwnerControlledConfig) -> Self {
        Self(PolicyManager::new(
            PolicyAuthority::OwnerControlled,
            config.initial_policy_root(),
        ))
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Registers an additional policy root in the allowed-policies list.
    ///
    /// If `policy_root` is already in the set, this is a no-op.
    pub fn with_allowed_policy(self, policy_root: Word) -> Self {
        Self(self.0.with_allowed_policy(policy_root))
    }

    /// Returns the authority used by this manager.
    pub fn authority(&self) -> PolicyAuthority {
        self.0.authority()
    }

    /// Returns the active policy procedure root.
    pub fn active_policy(&self) -> Word {
        self.0.active_policy()
    }

    /// Returns the allowed policy procedure roots.
    pub fn allowed_policies(&self) -> &[Word] {
        self.0.allowed_policies()
    }

    /// Returns the [`StorageSlotName`] where the active policy procedure root is stored.
    pub fn active_policy_slot() -> &'static StorageSlotName {
        PolicyManager::<BurnPolicyKind>::active_policy_slot()
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policies_slot() -> &'static StorageSlotName {
        PolicyManager::<BurnPolicyKind>::allowed_policies_slot()
    }

    /// Returns the [`StorageSlotName`] containing the policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        PolicyManager::<BurnPolicyKind>::policy_authority_slot()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        PolicyManager::<BurnPolicyKind>::component_metadata()
    }
}

impl From<BurnPolicyManager> for AccountComponent {
    fn from(manager: BurnPolicyManager) -> Self {
        manager.0.into()
    }
}
