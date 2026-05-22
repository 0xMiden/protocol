use alloc::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::component::{SchemaType, StorageSlotSchema};
use miden_protocol::account::{AccountId, StorageMap, StorageMapKey, StorageSlot, StorageSlotName};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::utils::sync::LazyLock;

mod owner_controlled;

pub use owner_controlled::BlocklistOwnerControlled;

// BLOCKED ACCOUNTS STORAGE
// ================================================================================================

static BLOCKED_ACCOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::transfer::blocklist::blocked_accounts",
    )
    .expect("storage slot name should be valid")
});

/// Storage backing the per-faucet blocklist.
///
/// `BlocklistStorage` exposes the slot name and schema for the `blocked_accounts` map plus an
/// optional initial set of blocked accounts. It is **not** an installable account component on
/// its own — the policy component that installs the storage map (typically
/// [`super::BasicBlocklist`]) reads the slot name and the initial entries from here.
///
/// The low-level `block_account` / `unblock_account` / `is_blocked` / `assert_not_blocked`
/// procedures live in the standards library at
/// `miden::standards::faucets::policies::transfer::blocklist` as `Invocation: exec` helpers —
/// they perform no authorization and must be wrapped by an auth-checking admin component (see
/// [`BlocklistOwnerControlled`]) before being exposed on a faucet.
///
/// ## Storage
///
/// - [`Self::blocked_accounts_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`). An account is considered blocked when its entry is
///   the word `[1, 0, 0, 0]`; the zero word (including the default for unset entries) means not
///   blocked.
#[derive(Debug, Clone, Default)]
pub struct BlocklistStorage {
    blocked_accounts: BTreeSet<AccountId>,
}

impl BlocklistStorage {
    /// Creates a [`BlocklistStorage`] with no initially blocked accounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`BlocklistStorage`] with the given blocked accounts.
    ///
    /// Duplicate account IDs are deduplicated by the underlying set.
    pub fn with_blocked_accounts(blocked_accounts: impl IntoIterator<Item = AccountId>) -> Self {
        Self {
            blocked_accounts: blocked_accounts.into_iter().collect(),
        }
    }

    /// Returns the initial blocked accounts captured in this storage.
    pub fn blocked_accounts(&self) -> &BTreeSet<AccountId> {
        &self.blocked_accounts
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

    /// Builds the initial `blocked_accounts` [`StorageMap`] from the captured set, marking each
    /// account ID's map entry with the `[1, 0, 0, 0]` blocked-flag word.
    pub fn build_storage_map(&self) -> StorageMap {
        let blocked_word = Word::from([1u32, 0, 0, 0]);
        StorageMap::with_entries(
            self.blocked_accounts
                .iter()
                .map(|id| (StorageMapKey::new(AccountIdKey::from(*id).as_word()), blocked_word)),
        )
        .expect("initial blocked accounts should have unique IDs")
    }

    /// Consumes the storage and returns the [`StorageSlot`] it contributes to an account
    /// component. The `blocked_accounts` map populated with the initial entries.
    pub fn into_slot(self) -> StorageSlot {
        StorageSlot::with_map(BLOCKED_ACCOUNTS_SLOT_NAME.clone(), self.build_storage_map())
    }
}
