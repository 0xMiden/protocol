use alloc::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::component::{SchemaType, StorageSlotSchema};
use miden_protocol::account::{AccountId, StorageMap, StorageMapKey, StorageSlot, StorageSlotName};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::utils::sync::LazyLock;

mod owner_controlled;

pub use owner_controlled::AllowlistOwnerControlled;

// ALLOWED ACCOUNTS STORAGE
// ================================================================================================

static ALLOWED_ACCOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::transfer::allowlist::allowed_accounts",
    )
    .expect("storage slot name should be valid")
});

/// Storage backing the per-faucet allowlist.
///
/// `AllowlistStorage` exposes the slot name and schema for the `allowed_accounts` map plus an
/// optional initial set of allowed accounts. It is **not** an installable account component on
/// its own — the policy component that installs the storage map (typically
/// [`super::BasicAllowlist`]) reads the slot name and the initial entries from here.
///
/// ## Storage
///
/// - [`Self::allowed_accounts_slot()`]: storage map keyed by account ID (word layout `[0, 0,
///   account_id_suffix, account_id_prefix]`). An account is considered allowed when its entry is
///   the word `[1, 0, 0, 0]`; the zero word (including the default for unset entries) means not
///   allowed. This is the opposite of the blocklist default — a faucet with an empty allowlist
///   rejects every transfer.
#[derive(Debug, Clone, Default)]
pub struct AllowlistStorage {
    allowed_accounts: BTreeSet<AccountId>,
}

impl AllowlistStorage {
    /// Creates an [`AllowlistStorage`] with no initially allowed accounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an [`AllowlistStorage`] with the given allowed accounts.
    ///
    /// Duplicate account IDs are deduplicated by the underlying set.
    pub fn with_allowed_accounts(allowed_accounts: impl IntoIterator<Item = AccountId>) -> Self {
        Self {
            allowed_accounts: allowed_accounts.into_iter().collect(),
        }
    }

    /// Returns the initial allowed accounts captured in this storage.
    pub fn allowed_accounts(&self) -> &BTreeSet<AccountId> {
        &self.allowed_accounts
    }

    /// Storage slot name for the allowed-accounts map.
    pub fn allowed_accounts_slot() -> &'static StorageSlotName {
        &ALLOWED_ACCOUNTS_SLOT_NAME
    }

    /// Schema entry for the allowed-accounts map slot (documentation / tooling).
    pub fn allowed_accounts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::allowed_accounts_slot().clone(),
            StorageSlotSchema::map(
                "Per-account allowed flag; zero word is not allowed, [1,0,0,0] is allowed",
                SchemaType::native_word(),
                SchemaType::bool(),
            ),
        )
    }

    /// Builds the initial `allowed_accounts` [`StorageMap`] from the captured set, marking each
    /// account ID's map entry with the `[1, 0, 0, 0]` allowed-flag word.
    pub fn build_storage_map(&self) -> StorageMap {
        let allowed_word = Word::from([1u32, 0, 0, 0]);
        StorageMap::with_entries(
            self.allowed_accounts
                .iter()
                .map(|id| (StorageMapKey::new(AccountIdKey::from(*id).as_word()), allowed_word)),
        )
        .expect("initial allowed accounts should have unique IDs")
    }

    /// Consumes the storage and returns the [`StorageSlot`] it contributes to an account
    /// component. The `allowed_accounts` map populated with the initial entries.
    pub fn into_slot(self) -> StorageSlot {
        StorageSlot::with_map(ALLOWED_ACCOUNTS_SLOT_NAME.clone(), self.build_storage_map())
    }
}
