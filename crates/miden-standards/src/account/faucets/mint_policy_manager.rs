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
use crate::procedure_digest;

// CONSTANTS
// ================================================================================================

procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    MintPolicyManager::NAME,
    MintPolicyManager::OWNER_ONLY_PROC_NAME,
    mint_policy_manager_library
);

static ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});
static ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});

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
#[derive(Debug, Clone, Copy)]
pub struct MintPolicyManager {
    initial_policy_root: Word,
}

/// Initial policy configuration for the [`MintPolicyManager`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintPolicy {
    /// Sets the initial policy to `owner_only`.
    #[default]
    OwnerOnly,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

impl MintPolicyManager {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::mint_policy_manager";

    const OWNER_ONLY_PROC_NAME: &str = "owner_only";

    /// Creates a new [`MintPolicyManager`] component from the provided configuration.
    pub fn new(policy: MintPolicy) -> Self {
        let initial_policy_root = match policy {
            MintPolicy::OwnerOnly => Self::owner_only_policy_root(),
            MintPolicy::CustomInitialRoot(root) => root,
        };

        Self { initial_policy_root }
    }

    /// Creates a new [`MintPolicyManager`] component with owner-only policy as default.
    pub fn owner_only() -> Self {
        Self::new(MintPolicy::OwnerOnly)
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
                "The procedure root of the active mint policy in the mint policy manager",
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
                "The set of allowed mint policy procedure roots in the mint policy manager",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the default owner-only policy root.
    pub fn owner_only_policy_root() -> Word {
        *OWNER_ONLY_POLICY_ROOT
    }
}

impl Default for MintPolicyManager {
    fn default() -> Self {
        Self::owner_only()
    }
}

impl From<MintPolicyManager> for AccountComponent {
    fn from(mint_policy_manager: MintPolicyManager) -> Self {
        let active_policy_proc_root_slot = StorageSlot::with_value(
            MintPolicyManager::active_policy_proc_root_slot().clone(),
            mint_policy_manager.initial_policy_root,
        );
        let allowed_policy_flag = Word::from([1u32, 0, 0, 0]);
        let owner_only_policy_root = MintPolicyManager::owner_only_policy_root();

        let mut allowed_policy_entries =
            vec![(StorageMapKey::from_raw(owner_only_policy_root), allowed_policy_flag.clone())];

        if mint_policy_manager.initial_policy_root != owner_only_policy_root {
            allowed_policy_entries.push((
                StorageMapKey::from_raw(mint_policy_manager.initial_policy_root),
                allowed_policy_flag,
            ));
        }

        let allowed_policy_proc_roots = StorageMap::with_entries(allowed_policy_entries)
            .expect("allowed mint policy roots should have unique keys");

        let allowed_policy_proc_roots_slot = StorageSlot::with_map(
            MintPolicyManager::allowed_policy_proc_roots_slot().clone(),
            allowed_policy_proc_roots,
        );

        let storage_schema = StorageSchema::new(vec![
            MintPolicyManager::active_policy_proc_root_slot_schema(),
            MintPolicyManager::allowed_policy_proc_roots_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata =
            AccountComponentMetadata::new(MintPolicyManager::NAME, [AccountType::FungibleFaucet])
                .with_description("Mint policy manager component for network fungible faucets")
                .with_storage_schema(storage_schema);

        AccountComponent::new(
            mint_policy_manager_library(),
            vec![active_policy_proc_root_slot, allowed_policy_proc_roots_slot],
            metadata,
        )
        .expect(
            "mint policy manager component should satisfy the requirements of a valid account component",
        )
    }
}
