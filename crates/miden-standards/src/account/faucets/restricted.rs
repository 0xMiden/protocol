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

use crate::account::components::restricted_library;
use crate::procedure_digest;

// RESTRICTED ACCOUNT COMPONENT
// ================================================================================================

static BLOCKED_ACCOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::restricted::blocked_accounts")
        .expect("storage slot name should be valid")
});

procedure_digest!(
    RESTRICTED_BLOCK,
    Restricted::NAME,
    Restricted::BLOCK_PROC_NAME,
    restricted_library
);

procedure_digest!(
    RESTRICTED_UNBLOCK,
    Restricted::NAME,
    Restricted::UNBLOCK_PROC_NAME,
    restricted_library
);

/// Faucet account component that stores a per-account blocked-accounts map plus the `block` /
/// `unblock` admin procedures. The component is intentionally callback-free: enforcement is
/// performed by the `if_not_blocklisted` transfer policy procedure, which the
/// [`crate::account::policies::TokenPolicyManager`] dispatches via `dynexec` from its
/// `on_before_asset_added_to_*` callbacks.
///
/// `block` and `unblock` do not authenticate the caller — this is an intentional choice:
/// the core mechanism is kept without access control so that owner and role-based access control
/// can be implemented on top without duplicating the block/unblock logic.
///
/// ## Storage
///
/// - [`Self::blocked_accounts_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`). An account is considered blocked when its entry is
///   the word `[1, 0, 0, 0]`; the zero word (including the default for unset entries) means not
///   blocked.
#[derive(Debug, Clone, Copy, Default)]
pub struct Restricted;

impl Restricted {
    /// Component library path (merged account module name).
    pub const NAME: &'static str = "miden::standards::components::faucets::restricted";

    const BLOCK_PROC_NAME: &'static str = "block";
    const UNBLOCK_PROC_NAME: &'static str = "unblock";

    /// Creates a new [`Restricted`] with an empty blocked-accounts map.
    pub const fn new() -> Self {
        Self
    }

    /// Storage slot name for the blocked-accounts map.
    pub fn blocked_accounts_slot() -> &'static StorageSlotName {
        &BLOCKED_ACCOUNTS_SLOT_NAME
    }

    /// Schema entry for the blocked-accounts map slot (documentation / tooling).
    pub fn blocked_accounts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::blocked_accounts_slot().clone(),
            StorageSlotSchema::map(
                "Per-account blocked flag; zero word is not blocked, [1,0,0,0] is blocked",
                SchemaType::native_word(),
                SchemaType::bool(),
            ),
        )
    }

    /// Metadata for accounts that include this component (faucet types that may issue
    /// callback-enabled assets).
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::blocked_accounts_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(
            Self::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Restricted faucet component: blocked-accounts storage map plus block/unblock admin \
             procedures (no callbacks; pair with the `if_not_blocklisted` transfer policy)",
        )
        .with_storage_schema(storage_schema)
    }

    pub fn block_digest() -> Word {
        *RESTRICTED_BLOCK
    }

    pub fn unblock_digest() -> Word {
        *RESTRICTED_UNBLOCK
    }
}

impl From<Restricted> for AccountComponent {
    fn from(_restricted: Restricted) -> Self {
        let blocked_accounts_slot = StorageSlot::with_map(
            Restricted::blocked_accounts_slot().clone(),
            StorageMap::default(),
        );

        let metadata = Restricted::component_metadata();

        AccountComponent::new(restricted_library(), vec![blocked_accounts_slot], metadata).expect(
            "restricted component should satisfy the requirements of a valid account component",
        )
    }
}
