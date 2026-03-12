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

use crate::account::components::auth_tx_controlled_library;
use crate::procedure_digest;

// CONSTANTS
// ================================================================================================

procedure_digest!(
    AUTH_TX_CONTROLLED_POLICY_ROOT,
    AuthTxControlled::NAME,
    AuthTxControlled::AUTH_TX_CONTROLLED_PROC_NAME,
    auth_tx_controlled_library
);

static ACTIVE_MINT_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});
static ALLOWED_MINT_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});
static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] providing configurable mint-policy management for network faucets.
///
/// It reexports policy procedures from `miden::standards::mint_policies` and manager procedures
/// from `miden::standards::mint_policies::policy_manager`:
/// - `auth_tx_controlled`
/// - `set_mint_policy`
/// - `get_mint_policy`
///
/// ## Storage Layout
///
/// - [`Self::active_policy_proc_root_slot`]: Procedure root of the active mint policy.
/// - [`Self::allowed_policy_proc_roots_slot`]: Set of allowed mint policy procedure roots.
/// - [`Self::policy_authority_slot`]: Policy authority mode (`0` = tx auth, `1` = external owner).
#[derive(Debug, Clone, Copy)]
pub struct AuthTxControlled {
    initial_policy_root: Word,
}

/// Initial policy configuration for the [`AuthTxControlled`] component.
#[derive(Debug, Clone, Copy, Default)]
pub enum AuthTxControlledInitConfig {
    /// Sets the initial policy to `auth_tx_controlled`.
    #[default]
    AuthTxControlled,
    /// Sets a custom initial policy root.
    CustomInitialRoot(Word),
}

impl AuthTxControlled {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::mint_policies::auth_tx_controlled";

    const AUTH_TX_CONTROLLED_PROC_NAME: &str = "auth_tx_controlled";

    /// Creates a new [`AuthTxControlled`] component from the provided configuration.
    pub fn new(policy: AuthTxControlledInitConfig) -> Self {
        let initial_policy_root = match policy {
            AuthTxControlledInitConfig::AuthTxControlled => Self::auth_tx_controlled_policy_root(),
            AuthTxControlledInitConfig::CustomInitialRoot(root) => root,
        };

        Self { initial_policy_root }
    }

    /// Creates a new [`AuthTxControlled`] component with `auth_tx_controlled` policy as
    /// default.
    pub fn auth_tx_controlled() -> Self {
        Self::new(AuthTxControlledInitConfig::AuthTxControlled)
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
                "The procedure root of the active mint policy in the mint policy auth tx controlled component",
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
                "The set of allowed mint policy procedure roots in the mint policy auth tx controlled component",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`StorageSlotName`] containing policy authority mode.
    pub fn policy_authority_slot() -> &'static StorageSlotName {
        &POLICY_AUTHORITY_SLOT_NAME
    }

    /// Returns the storage slot schema for policy authority mode.
    pub fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::policy_authority_slot().clone(),
            StorageSlotSchema::value(
                "Policy authority mode (0 = tx auth, 1 = external owner)",
                [
                    FeltSchema::u8("policy_authority"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    /// Returns the default `auth_tx_controlled` policy root.
    pub fn auth_tx_controlled_policy_root() -> Word {
        *AUTH_TX_CONTROLLED_POLICY_ROOT
    }
}

impl Default for AuthTxControlled {
    fn default() -> Self {
        Self::auth_tx_controlled()
    }
}

impl From<AuthTxControlled> for AccountComponent {
    fn from(auth_tx_controlled: AuthTxControlled) -> Self {
        let active_policy_proc_root_slot = StorageSlot::with_value(
            AuthTxControlled::active_policy_proc_root_slot().clone(),
            auth_tx_controlled.initial_policy_root,
        );
        let allowed_policy_flag = Word::from([1u32, 0, 0, 0]);
        let auth_tx_controlled_policy_root = AuthTxControlled::auth_tx_controlled_policy_root();

        let mut allowed_policy_entries =
            vec![(StorageMapKey::from_raw(auth_tx_controlled_policy_root), allowed_policy_flag)];

        if auth_tx_controlled.initial_policy_root != auth_tx_controlled_policy_root {
            allowed_policy_entries.push((
                StorageMapKey::from_raw(auth_tx_controlled.initial_policy_root),
                allowed_policy_flag,
            ));
        }

        let allowed_policy_proc_roots = StorageMap::with_entries(allowed_policy_entries)
            .expect("allowed mint policy roots should have unique keys");

        let allowed_policy_proc_roots_slot = StorageSlot::with_map(
            AuthTxControlled::allowed_policy_proc_roots_slot().clone(),
            allowed_policy_proc_roots,
        );
        let policy_authority_slot = StorageSlot::with_value(
            AuthTxControlled::policy_authority_slot().clone(),
            Word::from([0u32, 0, 0, 0]),
        );

        let storage_schema = StorageSchema::new(vec![
            AuthTxControlled::active_policy_proc_root_slot_schema(),
            AuthTxControlled::allowed_policy_proc_roots_slot_schema(),
            AuthTxControlled::policy_authority_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata =
            AccountComponentMetadata::new(AuthTxControlled::NAME, [AccountType::FungibleFaucet])
                .with_description(
                    "Mint policy auth tx controlled component for network fungible faucets",
                )
                .with_storage_schema(storage_schema);

        AccountComponent::new(
            auth_tx_controlled_library(),
            vec![
                active_policy_proc_root_slot,
                allowed_policy_proc_roots_slot,
                policy_authority_slot,
            ],
            metadata,
        )
        .expect(
            "mint policy auth tx controlled component should satisfy the requirements of a valid account component",
        )
    }
}
