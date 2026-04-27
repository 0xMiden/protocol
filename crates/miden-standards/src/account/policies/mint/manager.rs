use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, StorageSlotName};
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use super::{MintAllowAll, MintOwnerControlledConfig};
use crate::account::components::mint_policy_manager_library;
use crate::account::policies::PolicyAuthority;
use crate::account::policies::manager::{MintPolicyKind, PolicyKind, PolicyManager};

// STORAGE SLOT NAMES
// ================================================================================================

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::mint::policy_manager::policy_authority",
    )
    .expect("storage slot name should be valid")
});

static ACTIVE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::mint::policy_manager::active_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

static ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::mint::policy_manager::allowed_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

// POLICY KIND IMPL
// ================================================================================================

impl PolicyKind for MintPolicyKind {
    const COMPONENT_NAME: &'static str =
        "miden::standards::components::faucets::policies::mint::policy_manager";
    const COMPONENT_DESCRIPTION: &'static str = "Mint policy manager for fungible faucets";
    const ACTIVE_POLICY_DESC: &'static str = "Active mint policy procedure root";
    const ALLOWED_POLICIES_DESC: &'static str = "Allowed mint policy procedure roots";
    const AUTHORITY_DESC: &'static str = "Mint policy authority";
    const AUTHORITY_FELT_LABEL: &'static str = "mint_policy_authority";

    fn library() -> Library {
        mint_policy_manager_library()
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

// MINT POLICY MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the three policy-manager storage slots and the manager
/// procedures for the mint side.
///
/// Pair with at least one mint policy component (e.g. [`MintAllowAll`], [`MintOwnerOnly`]) whose
/// procedure root is registered in this manager's allowed-policies map.
#[derive(Debug, Clone)]
pub struct MintPolicyManager(PolicyManager<MintPolicyKind>);

impl MintPolicyManager {
    // KIND-SPECIFIC CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Convenience: an auth-controlled mint policy manager with `allow_all` as the active (and
    /// only allowed) policy.
    pub fn auth_controlled() -> Self {
        Self(PolicyManager::new(PolicyAuthority::AuthControlled, MintAllowAll::root()))
    }

    /// Convenience: an owner-controlled mint policy manager. Only the policy chosen by `config`
    /// is registered as allowed; if you want to permit runtime switching to another policy,
    /// register it explicitly via [`Self::with_allowed_policy`] and add the corresponding policy
    /// component to the account.
    pub fn owner_controlled(config: MintOwnerControlledConfig) -> Self {
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
        PolicyManager::<MintPolicyKind>::active_policy_slot()
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policies_slot() -> &'static StorageSlotName {
        PolicyManager::<MintPolicyKind>::allowed_policies_slot()
    }

    /// Returns the [`StorageSlotName`] containing the policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        PolicyManager::<MintPolicyKind>::policy_authority_slot()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        PolicyManager::<MintPolicyKind>::component_metadata()
    }
}

impl From<MintPolicyManager> for AccountComponent {
    fn from(manager: MintPolicyManager) -> Self {
        manager.0.into()
    }
}
