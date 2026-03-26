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

use super::MintPolicyAuthority;
use crate::account::components::owner_controlled_library;
use crate::account::policy_manager::OwnerControlled;
use crate::procedure_digest;

// MINT POLICY OWNER CONTROLLED
// ================================================================================================

// Initialize the digest of the `owner_only` procedure of the mint owner-controlled policy component
// only once.
procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    MintOwnerControlled::NAME,
    MintOwnerControlled::OWNER_ONLY_PROC_NAME,
    owner_controlled_library
);

static ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});
static ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});

/// Initial policy configuration for the [`MintOwnerControlled`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintOwnerControlledConfig {
    /// Sets the initial policy to `owner_only`.
    #[default]
    OwnerOnly,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

/// An [`AccountComponent`] providing configurable mint-policy management for network faucets.
///
/// It reexports policy procedures from `miden::standards::mint_policies` and manager procedures
/// from `miden::standards::mint_policies::policy_manager`:
/// - `owner_only`
/// - `set_mint_policy`
/// - `get_mint_policy`
///
/// ## Storage Layout
///
/// - [`Self::active_policy_proc_root_slot`]: Procedure root of the active mint policy.
/// - [`Self::allowed_policy_proc_roots_slot`]: Set of allowed mint policy procedure roots.
/// - [`Self::policy_authority_slot`]: Policy authority mode
///   ([`MintPolicyAuthority::AuthControlled`] = tx auth, [`MintPolicyAuthority::OwnerControlled`] =
///   external owner).
#[derive(Debug, Clone, Copy)]
pub struct MintOwnerControlled(OwnerControlled);

impl MintOwnerControlled {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::mint_policies::owner_controlled";

    const OWNER_ONLY_PROC_NAME: &str = "owner_only";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`MintOwnerControlled`] component from the provided configuration.
    pub fn new(policy: MintOwnerControlledConfig) -> Self {
        let initial_policy_root = match policy {
            MintOwnerControlledConfig::OwnerOnly => Self::owner_only_policy_root(),
            MintOwnerControlledConfig::CustomInitialRoot(root) => root,
        };

        Self(OwnerControlled { initial_policy_root })
    }

    /// Creates a new [`MintOwnerControlled`] component with owner-only policy as default.
    pub fn owner_only() -> Self {
        Self::new(MintOwnerControlledConfig::OwnerOnly)
    }

    /// Returns the [`StorageSlotName`] where the active mint policy procedure root is stored.
    pub fn active_policy_proc_root_slot() -> &'static StorageSlotName {
        &ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn allowed_policy_proc_roots_slot() -> &'static StorageSlotName {
        &ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME
    }

    /// Returns the storage slot schema for the active mint policy root.
    pub fn active_policy_proc_root_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::active_policy_proc_root_slot().clone(),
            StorageSlotSchema::value(
                "The procedure root of the active mint policy in the mint policy owner controlled component",
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
                "The set of allowed mint policy procedure roots in the mint policy owner controlled component",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`StorageSlotName`] containing policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        MintPolicyAuthority::slot()
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
    /// ([`MintPolicyAuthority::OwnerControlled`]).
    pub fn policy_authority_value_slot() -> StorageSlot {
        StorageSlot::from(MintPolicyAuthority::OwnerControlled)
    }

    /// Returns the default owner-only policy root.
    pub fn owner_only_policy_root() -> Word {
        *OWNER_ONLY_POLICY_ROOT
    }

    /// Returns the policy authority used by this component.
    pub fn mint_policy_authority(&self) -> MintPolicyAuthority {
        MintPolicyAuthority::OwnerControlled
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            MintOwnerControlled::active_policy_proc_root_slot_schema(),
            MintOwnerControlled::allowed_policy_proc_roots_slot_schema(),
            MintOwnerControlled::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(MintOwnerControlled::NAME, [AccountType::FungibleFaucet])
            .with_description("Mint policy owner controlled component for network fungible faucets")
            .with_storage_schema(storage_schema)
    }
}

impl Default for MintOwnerControlled {
    fn default() -> Self {
        Self::owner_only()
    }
}

impl From<MintOwnerControlled> for AccountComponent {
    fn from(mint_owner_controlled: MintOwnerControlled) -> Self {
        let slots = mint_owner_controlled.0.mint_initial_storage_slots(
            MintOwnerControlled::active_policy_proc_root_slot(),
            MintOwnerControlled::allowed_policy_proc_roots_slot(),
            MintOwnerControlled::policy_authority_value_slot(),
            MintOwnerControlled::owner_only_policy_root(),
        );

        let metadata = MintOwnerControlled::component_metadata();

        AccountComponent::new(owner_controlled_library(), slots, metadata).expect(
            "mint policy owner controlled component should satisfy the requirements of a valid account component",
        )
    }
}
