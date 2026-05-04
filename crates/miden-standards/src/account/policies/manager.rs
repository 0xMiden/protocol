//! Unified token policy manager.
//!
//! [`TokenPolicyManager`] owns the five storage slots (shared authority + active/allowed maps for
//! mint and burn) and exposes the management procedures via a single MASM library.

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

use super::PolicyAuthority;
use super::burn::BurnPolicyConfig;
use super::mint::MintPolicyConfig;
use crate::account::components::policy_manager_library;

// STORAGE SLOT NAMES
// ================================================================================================

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::policies::policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

static ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::active_mint_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

static ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::active_burn_policy_proc_root",
    )
    .expect("storage slot name should be valid")
});

static ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::allowed_mint_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

static ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::policy_manager::allowed_burn_policy_proc_roots",
    )
    .expect("storage slot name should be valid")
});

// TOKEN POLICY MANAGER
// ================================================================================================

/// An [`AccountComponent`] that owns the policy-manager storage slots and the manager
/// procedures for both mint and burn sides.
///
/// The component exposes `set_*_policy`, `get_*_policy`, and `execute_*_policy` procedures for
/// both mint and burn. The shared [`PolicyAuthority`] mode controls who can change either policy:
/// - [`PolicyAuthority::AuthControlled`]: changes are gated by the account's authentication
///   component.
/// - [`PolicyAuthority::OwnerControlled`]: changes require the account owner (verified through the
///   `Ownable2Step` companion component).
///
/// Construct via [`Self::new`] and pass the manager directly to
/// [`miden_protocol::account::AccountBuilder::with_components`] (the type implements
/// [`IntoIterator<Item = AccountComponent>`]). Iteration yields up to three components: the
/// policy manager itself, the chosen mint policy component, and the chosen burn policy
/// component. Custom policy variants are skipped — install the matching components on the
/// account separately. To register additional allowed roots for runtime switching, call
/// [`Self::with_allowed_mint_policy`] / [`Self::with_allowed_burn_policy`] and add the
/// matching policy components to the account separately.
///
/// ## Storage layout
///
/// - [`Self::policy_authority_slot`]: shared authority mode.
/// - [`Self::active_mint_policy_slot`]: procedure root of the active mint policy.
/// - [`Self::active_burn_policy_slot`]: procedure root of the active burn policy.
/// - [`Self::allowed_mint_policies_slot`]: map of allowed mint policy roots.
/// - [`Self::allowed_burn_policies_slot`]: map of allowed burn policy roots.
#[derive(Debug, Clone)]
pub struct TokenPolicyManager {
    authority: PolicyAuthority,
    mint_policy: MintPolicyConfig,
    burn_policy: BurnPolicyConfig,
    extra_allowed_mint_policies: Vec<Word>,
    extra_allowed_burn_policies: Vec<Word>,
}

impl TokenPolicyManager {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::policy_manager";

    /// Component description used in [`AccountComponentMetadata`].
    pub const DESCRIPTION: &'static str = "Token policy manager for fungible faucets";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new token policy manager configured with the given authority and the initial
    /// active mint and burn policies. Only the chosen policies are registered as allowed by
    /// default; runtime switching to additional policies requires explicit opt-in via
    /// [`Self::with_allowed_mint_policy`] / [`Self::with_allowed_burn_policy`] plus installing the
    /// corresponding policy components.
    pub fn new(
        authority: PolicyAuthority,
        mint_policy: MintPolicyConfig,
        burn_policy: BurnPolicyConfig,
    ) -> Self {
        Self {
            authority,
            mint_policy,
            burn_policy,
            extra_allowed_mint_policies: Vec::new(),
            extra_allowed_burn_policies: Vec::new(),
        }
    }

    /// Registers an additional mint policy root in the allowed-policies list.
    ///
    /// If `policy_root` is already in the set (including the active mint policy's root), this is a
    /// no-op. The corresponding policy component must be added to the account separately.
    pub fn with_allowed_mint_policy(mut self, policy_root: Word) -> Self {
        if policy_root != self.mint_policy.root()
            && !self.extra_allowed_mint_policies.contains(&policy_root)
        {
            self.extra_allowed_mint_policies.push(policy_root);
        }
        self
    }

    /// Registers an additional burn policy root in the allowed-policies list.
    ///
    /// If `policy_root` is already in the set (including the active burn policy's root), this is a
    /// no-op. The corresponding policy component must be added to the account separately.
    pub fn with_allowed_burn_policy(mut self, policy_root: Word) -> Self {
        if policy_root != self.burn_policy.root()
            && !self.extra_allowed_burn_policies.contains(&policy_root)
        {
            self.extra_allowed_burn_policies.push(policy_root);
        }
        self
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the authority used by this manager.
    pub fn authority(&self) -> PolicyAuthority {
        self.authority
    }

    /// Returns the active mint policy procedure root.
    pub fn active_mint_policy(&self) -> Word {
        self.mint_policy.root()
    }

    /// Returns the active burn policy procedure root.
    pub fn active_burn_policy(&self) -> Word {
        self.burn_policy.root()
    }

    /// Returns the allowed mint policy procedure roots (including the active root).
    pub fn allowed_mint_policies(&self) -> Vec<Word> {
        let mut roots = vec![self.mint_policy.root()];
        roots.extend(self.extra_allowed_mint_policies.iter().copied());
        roots
    }

    /// Returns the allowed burn policy procedure roots (including the active root).
    pub fn allowed_burn_policies(&self) -> Vec<Word> {
        let mut roots = vec![self.burn_policy.root()];
        roots.extend(self.extra_allowed_burn_policies.iter().copied());
        roots
    }

    /// Returns the [`StorageSlotName`] containing the policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        &POLICY_AUTHORITY_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active mint policy procedure root is stored.
    pub fn active_mint_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the active burn policy procedure root is stored.
    pub fn active_burn_policy_slot() -> &'static StorageSlotName {
        &ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed mint policy roots are stored.
    pub fn allowed_mint_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed burn policy roots are stored.
    pub fn allowed_burn_policies_slot() -> &'static StorageSlotName {
        &ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            (
                POLICY_AUTHORITY_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Token policy authority",
                    [
                        FeltSchema::u8("policy_authority"),
                        FeltSchema::new_void(),
                        FeltSchema::new_void(),
                        FeltSchema::new_void(),
                    ],
                ),
            ),
            (
                ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Active mint policy procedure root",
                    SchemaType::native_word(),
                ),
            ),
            (
                ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                StorageSlotSchema::value(
                    "Active burn policy procedure root",
                    SchemaType::native_word(),
                ),
            ),
            (
                ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Allowed mint policy procedure roots",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
            (
                ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                StorageSlotSchema::map(
                    "Allowed burn policy procedure roots",
                    SchemaType::native_word(),
                    SchemaType::native_word(),
                ),
            ),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description(Self::DESCRIPTION)
            .with_storage_schema(storage_schema)
    }

    fn manager_storage_slots(&self) -> Vec<StorageSlot> {
        let allowed_flag = Word::from([1u32, 0, 0, 0]);

        let allowed_mint_entries: Vec<_> = self
            .allowed_mint_policies()
            .into_iter()
            .map(|root| (StorageMapKey::from_raw(root), allowed_flag))
            .collect();
        let allowed_mint_map = StorageMap::with_entries(allowed_mint_entries)
            .expect("allowed mint policy roots should have unique keys");

        let allowed_burn_entries: Vec<_> = self
            .allowed_burn_policies()
            .into_iter()
            .map(|root| (StorageMapKey::from_raw(root), allowed_flag))
            .collect();
        let allowed_burn_map = StorageMap::with_entries(allowed_burn_entries)
            .expect("allowed burn policy roots should have unique keys");

        vec![
            StorageSlot::with_value(POLICY_AUTHORITY_SLOT_NAME.clone(), self.authority.into()),
            StorageSlot::with_value(
                ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.mint_policy.root(),
            ),
            StorageSlot::with_value(
                ACTIVE_BURN_POLICY_PROC_ROOT_SLOT_NAME.clone(),
                self.burn_policy.root(),
            ),
            StorageSlot::with_map(
                ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                allowed_mint_map,
            ),
            StorageSlot::with_map(
                ALLOWED_BURN_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
                allowed_burn_map,
            ),
        ]
    }

    fn into_manager_component(self) -> AccountComponent {
        let storage_slots = self.manager_storage_slots();
        AccountComponent::new(
            policy_manager_library(),
            storage_slots,
            Self::component_metadata(),
        )
        .expect(
            "token policy manager component should satisfy the requirements of a valid account component",
        )
    }
}

impl IntoIterator for TokenPolicyManager {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this token policy configuration, in the
    /// order they must be installed on the account:
    ///
    /// 1. The policy manager component (storage slots + manager procedures).
    /// 2. The active mint policy component (resolved from the [`MintPolicyConfig`] passed to
    ///    [`TokenPolicyManager::new`]), if it resolves to a built-in component.
    /// 3. The active burn policy component (resolved from the [`BurnPolicyConfig`]), if it resolves
    ///    to a built-in component.
    ///
    /// [`MintPolicyConfig::Custom`] / [`BurnPolicyConfig::Custom`] variants are skipped — the
    /// caller must install the corresponding components on the account separately.
    ///
    /// To register additional allowed policies for runtime switching, call
    /// [`Self::with_allowed_mint_policy`] / [`Self::with_allowed_burn_policy`] and add the
    /// matching policy components to the account separately.
    fn into_iter(self) -> Self::IntoIter {
        let mint_policy = self.mint_policy;
        let burn_policy = self.burn_policy;
        let manager_component = self.into_manager_component();

        let mut components = vec![manager_component];
        components.extend(mint_policy.into_component());
        components.extend(burn_policy.into_component());
        components.into_iter()
    }
}
