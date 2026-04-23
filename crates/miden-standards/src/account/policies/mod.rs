//! Mint and burn policy account components and their policy managers.
//!
//! Policies are the procedures that gate minting and burning of tokens. Each side ([`mint`],
//! [`burn`]) exposes:
//! - A [`PolicyManager`] (via the kind-specific type aliases [`mint::PolicyManager`] /
//!   [`burn::PolicyManager`]) that owns the three manager storage slots and the `set_*_policy` /
//!   `get_*_policy` / `execute_*_policy` procedures.
//! - Storage-free policy components (e.g. `mint::AllowAll`, `mint::owner_controlled::OwnerOnly`)
//!   that install a specific policy procedure on the account.
//!
//! A faucet installs the manager together with at least one policy component whose procedure root
//! is registered in the manager's allowed-policies map.
//!
//! The manager itself is a single generic struct [`PolicyManager<K>`] where `K` is either
//! [`Mint`] or [`Burn`]. The [`PolicyKind`] trait encapsulates the kind-specific static data
//! (library, storage slot names, component name, schema labels). Shared construction logic lives
//! on `impl<K: PolicyKind> PolicyManager<K>`; kind-specific constructors (`auth_controlled`,
//! `owner_controlled`) live on `impl PolicyManager<Mint>` and `impl PolicyManager<Burn>`.

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

pub mod burn;
pub mod mint;

// MARKERS
// ================================================================================================

/// Marker type selecting the mint side of the policy manager.
#[derive(Debug, Clone, Copy)]
pub struct Mint;

/// Marker type selecting the burn side of the policy manager.
#[derive(Debug, Clone, Copy)]
pub struct Burn;

// POLICY AUTHORITY
// ================================================================================================

/// Identifies which authority is allowed to manage the active policy for a faucet.
///
/// Shared between mint and burn policy managers — the authority slot stores the same encoding
/// (`0` = `AuthControlled`, `1` = `OwnerControlled`) regardless of side.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAuthority {
    /// Policy changes are authorized by the account's authentication component logic.
    AuthControlled = 0,
    /// Policy changes are authorized by the external account owner.
    OwnerControlled = 1,
}

impl From<PolicyAuthority> for Word {
    fn from(value: PolicyAuthority) -> Self {
        Word::from([value as u8, 0, 0, 0])
    }
}

// POLICY KIND TRAIT
// ================================================================================================

/// Kind-specific static data for a [`PolicyManager`].
///
/// Implementors are the [`Mint`] and [`Burn`] marker types. The trait carries only static
/// constants / function lookups (library, storage slot names, component metadata) — no
/// "business logic"; kind-specific constructors live in inherent impls on
/// `PolicyManager<Mint>` / `PolicyManager<Burn>`.
pub trait PolicyKind: Copy {
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

/// An [`AccountComponent`] that owns the three policy-manager storage slots and the manager
/// procedures for its [`PolicyKind`].
///
/// Users typically interact via the kind-specific aliases [`mint::PolicyManager`] and
/// [`burn::PolicyManager`]. Kind-specific constructors (`auth_controlled`, `owner_controlled`)
/// live in those sides' inherent impls.
///
/// ## Storage layout
///
/// - [`Self::active_policy_slot`]: Procedure root of the active policy.
/// - [`Self::allowed_policies_slot`]: Map of allowed policy procedure roots.
/// - [`Self::policy_authority_slot`]: [`PolicyAuthority`] mode.
#[derive(Debug, Clone)]
pub struct PolicyManager<K: PolicyKind> {
    authority: PolicyAuthority,
    active_policy: Word,
    allowed_policies: Vec<Word>,
    _kind: PhantomData<K>,
}

impl<K: PolicyKind> PolicyManager<K> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new manager with the given authority and active policy root. The active policy is
    /// automatically added to the allowed-policies list.
    pub fn new(authority: PolicyAuthority, active_policy: Word) -> Self {
        Self {
            authority,
            active_policy,
            allowed_policies: vec![active_policy],
            _kind: PhantomData,
        }
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

    /// Returns the [`StorageSlotName`] where the active policy procedure root is stored.
    pub fn active_policy_slot() -> &'static StorageSlotName {
        K::active_policy_slot()
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policies_slot() -> &'static StorageSlotName {
        K::allowed_policies_slot()
    }

    /// Returns the [`StorageSlotName`] containing the policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        K::policy_authority_slot()
    }

    /// Returns the storage slot schema for the active policy root.
    pub fn active_policy_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            K::active_policy_slot().clone(),
            StorageSlotSchema::value(K::ACTIVE_POLICY_DESC, SchemaType::native_word()),
        )
    }

    /// Returns the storage slot schema for the allowed policy roots map.
    pub fn allowed_policies_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            K::allowed_policies_slot().clone(),
            StorageSlotSchema::map(
                K::ALLOWED_POLICIES_DESC,
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the storage slot schema for the policy authority mode.
    pub fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
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

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
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
