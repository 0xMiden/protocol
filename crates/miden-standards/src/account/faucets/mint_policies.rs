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

use crate::account::components::mint_policies_faucet_library;
use crate::procedure_digest;

// CONSTANTS
// ================================================================================================

procedure_digest!(
    MINT_POLICIES_OWNER_ONLY_POLICY_ROOT,
    MintPolicies::NAME,
    MintPolicies::MINT_POLICY_OWNER_ONLY_PROC_NAME,
    mint_policies_faucet_library
);

static MINT_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policies::proc_root")
        .expect("storage slot name should be valid")
});
static MINT_POLICY_ALLOWED_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policies::allowed_roots")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] providing configurable mint-policy management for network faucets.
///
/// It reexports policy procedures from `miden::standards::mint_policies` and manager procedures
/// from `miden::standards::mint_policies::policy_manager`:
/// - `mint_policy_owner_only`
/// - `set_mint_policy`
/// - `get_mint_policy`
///
/// ## Storage Layout
///
/// - [`Self::mint_policy_proc_root_slot`]: Active mint policy procedure root.
/// - [`Self::mint_policy_allowed_roots_slot`]: Allowed policy roots for `set_mint_policy`.
#[derive(Debug, Clone, Copy)]
pub struct MintPolicies {
    initial_policy_root: Word,
}

/// Initial policy configuration for the [`MintPolicies`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintPolicyConfig {
    /// Sets the initial policy to `mint_policy_owner_only`.
    #[default]
    OwnerOnly,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

impl MintPolicies {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::mint_policies";

    const MINT_POLICY_OWNER_ONLY_PROC_NAME: &str = "mint_policy_owner_only";

    /// Creates a new [`MintPolicies`] component from the provided configuration.
    pub fn new(config: MintPolicyConfig) -> Self {
        let initial_policy_root = match config {
            MintPolicyConfig::OwnerOnly => Self::owner_only_policy_root(),
            MintPolicyConfig::CustomInitialRoot(root) => root,
        };

        Self { initial_policy_root }
    }

    /// Creates a new [`MintPolicies`] component with owner-only policy as default.
    pub fn owner_only() -> Self {
        Self::new(MintPolicyConfig::OwnerOnly)
    }

    /// Returns the [`StorageSlotName`] where the active mint policy procedure root is stored.
    pub fn mint_policy_proc_root_slot() -> &'static StorageSlotName {
        &MINT_POLICY_PROC_ROOT_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where allowed policy roots are stored.
    pub fn mint_policy_allowed_roots_slot() -> &'static StorageSlotName {
        &MINT_POLICY_ALLOWED_ROOTS_SLOT_NAME
    }

    /// Returns the storage slot schema for the active mint policy root.
    pub fn mint_policy_proc_root_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::mint_policy_proc_root_slot().clone(),
            StorageSlotSchema::value(
                "Active mint policy procedure root",
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
    pub fn mint_policy_allowed_roots_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::mint_policy_allowed_roots_slot().clone(),
            StorageSlotSchema::map(
                "Allowed mint policy roots",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the default owner-only policy root.
    pub fn owner_only_policy_root() -> Word {
        *MINT_POLICIES_OWNER_ONLY_POLICY_ROOT
    }
}

impl Default for MintPolicies {
    fn default() -> Self {
        Self::owner_only()
    }
}

impl From<MintPolicies> for AccountComponent {
    fn from(mint_policies: MintPolicies) -> Self {
        let mint_policy_proc_root_slot = StorageSlot::with_value(
            MintPolicies::mint_policy_proc_root_slot().clone(),
            mint_policies.initial_policy_root,
        );

        let allowed_roots =
            if mint_policies.initial_policy_root == MintPolicies::owner_only_policy_root() {
                StorageMap::with_entries([(
                    StorageMapKey::from_raw(MintPolicies::owner_only_policy_root()),
                    Word::from([1u32, 0, 0, 0]),
                )])
            } else {
                StorageMap::with_entries([
                    (
                        StorageMapKey::from_raw(MintPolicies::owner_only_policy_root()),
                        Word::from([1u32, 0, 0, 0]),
                    ),
                    (
                        StorageMapKey::from_raw(mint_policies.initial_policy_root),
                        Word::from([1u32, 0, 0, 0]),
                    ),
                ])
            }
            .expect("allowed mint policy roots should have unique keys");

        let mint_policy_allowed_roots_slot = StorageSlot::with_map(
            MintPolicies::mint_policy_allowed_roots_slot().clone(),
            allowed_roots,
        );

        let storage_schema = StorageSchema::new(vec![
            MintPolicies::mint_policy_proc_root_slot_schema(),
            MintPolicies::mint_policy_allowed_roots_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata =
            AccountComponentMetadata::new(MintPolicies::NAME, [AccountType::FungibleFaucet])
                .with_description("Mint policy management component for network fungible faucets")
                .with_storage_schema(storage_schema);

        AccountComponent::new(
            mint_policies_faucet_library(),
            vec![mint_policy_proc_root_slot, mint_policy_allowed_roots_slot],
            metadata,
        )
        .expect(
            "mint policies component should satisfy the requirements of a valid account component",
        )
    }
}
