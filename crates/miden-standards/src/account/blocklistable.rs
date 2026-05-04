use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountType,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::blocklistable_library;
use crate::procedure_digest;

// BLOCKLISTABLE ACCOUNT COMPONENT
// ================================================================================================

static BLOCKLIST_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::utils::blocklistable::blocklist")
        .expect("storage slot name should be valid")
});

procedure_digest!(
    BLOCKLISTABLE_BLOCKLIST,
    Blocklistable::NAME,
    Blocklistable::BLOCKLIST_PROC_NAME,
    blocklistable_library
);

procedure_digest!(
    BLOCKLISTABLE_UNBLOCKLIST,
    Blocklistable::NAME,
    Blocklistable::UNBLOCKLIST_PROC_NAME,
    blocklistable_library
);

/// Account component that stores a per-account blocklist map plus the `blocklist` / `unblocklist`
/// admin procedures. The component is intentionally callback-free: enforcement is performed by
/// the `if_not_blocklisted` transfer policy procedure, which the
/// [`crate::account::policies::TokenPolicyManager`] dispatches via `dynexec` from its
/// `on_before_asset_added_to_*` callbacks.
///
/// `blocklist` and `unblocklist` do not authenticate the caller — this is an intentional choice:
/// the core mechanism is kept without access control so that owner and role-based access control
/// can be implemented on top without duplicating the blocklist/unblocklist logic.
///
/// ## Storage
///
/// - [`Self::blocklist_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`). An account is considered blocklisted when its entry
///   is the word `[1, 0, 0, 0]`; the zero word (including the default for unset entries) means not
///   blocklisted.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blocklistable;

impl Blocklistable {
    /// Component library path (merged account module name).
    pub const NAME: &'static str = "miden::standards::components::utils::blocklistable";

    const BLOCKLIST_PROC_NAME: &'static str = "blocklist";
    const UNBLOCKLIST_PROC_NAME: &'static str = "unblocklist";

    /// Creates a new [`Blocklistable`] with an empty blocklist.
    pub const fn new() -> Self {
        Self
    }

    /// Storage slot name for the blocklist map.
    pub fn blocklist_slot() -> &'static StorageSlotName {
        &BLOCKLIST_SLOT_NAME
    }

    /// Schema entry for the blocklist map slot (documentation / tooling).
    pub fn blocklist_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::blocklist_slot().clone(),
            StorageSlotSchema::map(
                "Per-account blocklist flag; zero word is not blocklisted, [1,0,0,0] is blocklisted",
                SchemaType::native_word(),
                SchemaType::bool(),
            ),
        )
    }

    /// Metadata for accounts that include this component (faucet types that may issue
    /// callback-enabled assets).
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::blocklist_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Blocklistable component: blocklist storage map plus blocklist/unblocklist admin \
             procedures (no callbacks; pair with the `if_not_blocklisted` transfer policy)",
        )
        .with_storage_schema(storage_schema)
    }

    pub fn blocklist_digest() -> Word {
        *BLOCKLISTABLE_BLOCKLIST
    }

    pub fn unblocklist_digest() -> Word {
        *BLOCKLISTABLE_UNBLOCKLIST
    }
}

impl From<Blocklistable> for AccountComponent {
    fn from(_blocklistable: Blocklistable) -> Self {
        let blocklist_slot =
            StorageSlot::with_map(Blocklistable::blocklist_slot().clone(), StorageMap::default());

        let metadata = Blocklistable::component_metadata();

        AccountComponent::new(blocklistable_library(), vec![blocklist_slot], metadata).expect(
            "blocklistable component should satisfy the requirements of a valid account component",
        )
    }
}
