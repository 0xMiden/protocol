use alloc::vec::Vec;

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

use crate::account::components::mint_policy_manager_library;
use crate::account::policies::mint::AllowAll;
use crate::account::policies::mint::owner_controlled::{MintOwnerControlledConfig, OwnerOnly};

// STORAGE SLOT NAMES
// ================================================================================================

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

static ACTIVE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});

static ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});

// POLICY AUTHORITY
// ================================================================================================

/// Identifies which authority is allowed to manage the active mint policy for a faucet.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAuthority {
    /// Mint policy changes are authorized by the account's authentication component logic.
    AuthControlled = 0,
    /// Mint policy changes are authorized by the external account owner.
    OwnerControlled = 1,
}

impl From<PolicyAuthority> for Word {
    fn from(value: PolicyAuthority) -> Self {
        Word::from([value as u8, 0, 0, 0])
    }
}

// MINT POLICY MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the storage and procedures of the mint policy manager.
///
/// Reexports the manager procedures from `miden::standards::policies::mint::policy_manager`:
/// - `set_mint_policy`
/// - `get_mint_policy`
/// - `execute_mint_policy`
///
/// Must be paired with at least one mint policy component (e.g. [`AllowAll`] or [`OwnerOnly`])
/// whose procedure root is registered in the allowed-policies map.
#[derive(Debug, Clone)]
pub struct PolicyManager {
    authority: PolicyAuthority,
    active_policy: Word,
    allowed_policies: Vec<Word>,
}

impl PolicyManager {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::policies::mint::policy_manager";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`PolicyManager`] with the given authority and active policy root. The active
    /// policy is automatically added to the allowed-policies list.
    pub fn new(authority: PolicyAuthority, active_policy: Word) -> Self {
        Self {
            authority,
            active_policy,
            allowed_policies: vec![active_policy],
        }
    }

    /// Convenience: an auth-controlled manager with `allow_all` as the active (and only allowed)
    /// policy.
    pub fn auth_controlled() -> Self {
        Self::new(PolicyAuthority::AuthControlled, AllowAll::root())
    }

    /// Convenience: an owner-controlled manager. The active policy is chosen by `config`;
    /// [`OwnerOnly::root`] is always registered in the allowed-policies list so the owner can
    /// switch to it at runtime if a different active policy was chosen initially.
    pub fn owner_controlled(config: MintOwnerControlledConfig) -> Self {
        Self::new(PolicyAuthority::OwnerControlled, config.initial_policy_root())
            .with_allowed_policy(OwnerOnly::root())
    }

    /// Registers an additional policy root in the allowed-policies list.
    pub fn with_allowed_policy(mut self, policy_root: Word) -> Self {
        if !self.allowed_policies.contains(&policy_root) {
            self.allowed_policies.push(policy_root);
        }
        self
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the authority used by this manager.
    pub fn authority(&self) -> PolicyAuthority {
        self.authority
    }

    /// Returns the active policy procedure root.
    pub fn active_policy(&self) -> Word {
        self.active_policy
    }

    /// Returns the allowed policy procedure roots.
    pub fn allowed_policies(&self) -> &[Word] {
        &self.allowed_policies
    }

    /// Returns the [`StorageSlotName`] where the active mint policy procedure root is stored.
    pub fn active_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] containing the policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        &POLICY_AUTHORITY_SLOT_NAME
    }

    /// Returns the storage slot schema for the active mint policy root.
    pub fn active_policy_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            ACTIVE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
            StorageSlotSchema::value(
                "Active mint policy procedure root",
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the storage slot schema for the allowed policy roots map.
    pub fn allowed_policies_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
            StorageSlotSchema::map(
                "Allowed mint policy procedure roots",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the storage slot schema for the policy authority mode.
    pub fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            POLICY_AUTHORITY_SLOT_NAME.clone(),
            StorageSlotSchema::value(
                "Mint policy authority",
                [
                    FeltSchema::u8("mint_policy_authority"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            Self::active_policy_slot_schema(),
            Self::allowed_policies_slot_schema(),
            Self::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description("Mint policy manager for fungible faucets")
            .with_storage_schema(storage_schema)
    }

    fn initial_storage_slots(&self) -> Vec<StorageSlot> {
        let allowed_flag = Word::from([1u32, 0, 0, 0]);
        let entries: Vec<_> = self
            .allowed_policies
            .iter()
            .map(|root| (StorageMapKey::from_raw(*root), allowed_flag))
            .collect();
        let allowed_map = StorageMap::with_entries(entries)
            .expect("allowed mint policy roots should have unique keys");

        vec![
            StorageSlot::with_value(ACTIVE_POLICY_PROC_ROOT_SLOT_NAME.clone(), self.active_policy),
            StorageSlot::with_map(ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME.clone(), allowed_map),
            StorageSlot::with_value(POLICY_AUTHORITY_SLOT_NAME.clone(), self.authority.into()),
        ]
    }
}

impl From<PolicyManager> for AccountComponent {
    fn from(manager: PolicyManager) -> Self {
        AccountComponent::new(
            mint_policy_manager_library(),
            manager.initial_storage_slots(),
            PolicyManager::component_metadata(),
        )
        .expect(
            "mint policy manager component should satisfy the requirements of a valid account component",
        )
    }
}
