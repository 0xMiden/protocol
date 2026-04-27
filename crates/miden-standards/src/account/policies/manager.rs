//! Internal generic policy manager plumbing.
//!
//! [`PolicyManager`] is parameterized by [`PolicyKind`] and provides shared construction logic for
//! both mint and burn policy managers. The kind-specific [`MintPolicyKind`] and [`BurnPolicyKind`]
//! markers carry the static data (library, slot names, schema labels) for each side.
//!
//! These types are intentionally crate-private. The public API exposes thin newtype wrappers
//! [`super::MintPolicyManager`] and [`super::BurnPolicyManager`].

use alloc::vec::Vec;
use core::marker::PhantomData;

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
use miden_protocol::assembly::Library;

use super::PolicyAuthority;

// MARKERS
// ================================================================================================

/// Marker type selecting the mint side of the policy manager.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MintPolicyKind;

/// Marker type selecting the burn side of the policy manager.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BurnPolicyKind;

// POLICY KIND TRAIT
// ================================================================================================

/// Kind-specific static data for a [`PolicyManager`].
///
/// Implementors are the [`MintPolicyKind`] and [`BurnPolicyKind`] marker types. The trait carries
/// only static constants / function lookups (library, storage slot names, component metadata) — no
/// "business logic"; kind-specific constructors live in inherent impls on the public newtype
/// wrappers [`super::MintPolicyManager`] / [`super::BurnPolicyManager`].
pub(crate) trait PolicyKind: Copy {
    /// Component name used in `AccountComponentMetadata`.
    const COMPONENT_NAME: &'static str;
    /// Component description used in `AccountComponentMetadata`.
    const COMPONENT_DESCRIPTION: &'static str;

    /// Schema label for the active-policy storage slot.
    const ACTIVE_POLICY_DESC: &'static str;
    /// Schema label for the allowed-policies storage slot.
    const ALLOWED_POLICIES_DESC: &'static str;
    /// Schema label for the policy-authority storage slot.
    const AUTHORITY_DESC: &'static str;
    /// Felt label on the authority slot (e.g. `"mint_policy_authority"`).
    const AUTHORITY_FELT_LABEL: &'static str;

    /// Compiled MASM library for this kind's policy manager component.
    fn library() -> Library;

    /// Storage slot name holding the active policy procedure root.
    fn active_policy_slot() -> &'static StorageSlotName;
    /// Storage slot name holding the allowed policy procedure roots map.
    fn allowed_policies_slot() -> &'static StorageSlotName;
    /// Storage slot name holding the policy authority mode.
    fn policy_authority_slot() -> &'static StorageSlotName;
}

// POLICY MANAGER (generic)
// ================================================================================================

/// Generic policy manager backing [`super::MintPolicyManager`] / [`super::BurnPolicyManager`].
///
/// ## Storage layout
///
/// - `active_policy_slot`: Procedure root of the active policy.
/// - `allowed_policies_slot`: Map of allowed policy procedure roots.
/// - `policy_authority_slot`: [`PolicyAuthority`] mode.
#[derive(Debug, Clone)]
pub(crate) struct PolicyManager<K: PolicyKind> {
    authority: PolicyAuthority,
    active_policy: Word,
    allowed_policies: Vec<Word>,
    _kind: PhantomData<K>,
}

impl<K: PolicyKind> PolicyManager<K> {
    /// Creates a new manager with the given authority and active policy root. The active policy is
    /// automatically added to the allowed-policies list.
    pub(crate) fn new(authority: PolicyAuthority, active_policy: Word) -> Self {
        Self {
            authority,
            active_policy,
            allowed_policies: vec![active_policy],
            _kind: PhantomData,
        }
    }

    /// Registers an additional policy root in the allowed-policies list.
    ///
    /// If `policy_root` is already in the set, this is a no-op.
    pub(crate) fn with_allowed_policy(mut self, policy_root: Word) -> Self {
        if !self.allowed_policies.contains(&policy_root) {
            self.allowed_policies.push(policy_root);
        }
        self
    }

    /// Returns the authority used by this manager.
    pub(crate) fn authority(&self) -> PolicyAuthority {
        self.authority
    }

    /// Returns the active policy procedure root.
    pub(crate) fn active_policy(&self) -> Word {
        self.active_policy
    }

    /// Returns the allowed policy procedure roots.
    pub(crate) fn allowed_policies(&self) -> &[Word] {
        &self.allowed_policies
    }

    pub(crate) fn active_policy_slot() -> &'static StorageSlotName {
        K::active_policy_slot()
    }

    pub(crate) fn allowed_policies_slot() -> &'static StorageSlotName {
        K::allowed_policies_slot()
    }

    pub(crate) fn policy_authority_slot() -> &'static StorageSlotName {
        K::policy_authority_slot()
    }

    pub(crate) fn active_policy_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            K::active_policy_slot().clone(),
            StorageSlotSchema::value(K::ACTIVE_POLICY_DESC, SchemaType::native_word()),
        )
    }

    pub(crate) fn allowed_policies_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            K::allowed_policies_slot().clone(),
            StorageSlotSchema::map(
                K::ALLOWED_POLICIES_DESC,
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub(crate) fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            K::policy_authority_slot().clone(),
            StorageSlotSchema::value(
                K::AUTHORITY_DESC,
                [
                    FeltSchema::u8(K::AUTHORITY_FELT_LABEL),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub(crate) fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            Self::active_policy_slot_schema(),
            Self::allowed_policies_slot_schema(),
            Self::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(K::COMPONENT_NAME, [AccountType::FungibleFaucet])
            .with_description(K::COMPONENT_DESCRIPTION)
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
            .expect("allowed policy roots should have unique keys");

        vec![
            StorageSlot::with_value(K::active_policy_slot().clone(), self.active_policy),
            StorageSlot::with_map(K::allowed_policies_slot().clone(), allowed_map),
            StorageSlot::with_value(K::policy_authority_slot().clone(), self.authority.into()),
        ]
    }
}

impl<K: PolicyKind> From<PolicyManager<K>> for AccountComponent {
    fn from(manager: PolicyManager<K>) -> Self {
        AccountComponent::new(
            K::library(),
            manager.initial_storage_slots(),
            PolicyManager::<K>::component_metadata(),
        )
        .expect(
            "policy manager component should satisfy the requirements of a valid account component",
        )
    }
}
