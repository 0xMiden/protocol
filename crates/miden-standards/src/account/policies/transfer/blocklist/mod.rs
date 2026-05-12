use miden_protocol::account::StorageSlotName;
use miden_protocol::account::component::{SchemaType, StorageSlotSchema};
use miden_protocol::utils::sync::LazyLock;

mod owner_managed;

pub use owner_managed::OwnerManagedBlocklist;

// BLOCKED ACCOUNTS STORAGE NAMESPACE
// ================================================================================================

static BLOCKED_ACCOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::transfer::blocklist::blocked_accounts",
    )
    .expect("storage slot name should be valid")
});

/// Namespace exposing accessors for the per-faucet `blocked_accounts` storage slot.
///
/// `Blocklist` is **not** an installable account component on its own — it just exposes the
/// slot name and schema so that policy and admin components can reference them. The storage
/// is installed by [`super::BasicBlocklist`] (the transfer policy component); the low-level
/// `block_account` / `unblock_account` / `is_blocked` / `assert_not_blocked` procedures live in
/// the standards library at `miden::standards::faucets::policies::transfer::blocklist` as
/// `Invocation: exec` helpers — they perform no authorization and must be wrapped by an
/// auth-checking admin component (see [`OwnerManagedBlocklist`]) before being exposed on a
/// faucet.
///
/// ## Storage
///
/// - [`Self::blocked_accounts_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`). An account is considered blocked when its entry is
///   the word `[1, 0, 0, 0]`; the zero word (including the default for unset entries) means not
///   blocked.
#[derive(Debug, Clone, Copy)]
pub struct Blocklist;

impl Blocklist {
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
}
