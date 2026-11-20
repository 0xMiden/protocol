use alloc::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::utils::sync::LazyLock;

use crate::account::account_component_package;
use crate::procedure_root;

mod manager;

pub use manager::AllowlistManager;

// ALLOWED ACCOUNTS STORAGE
// ================================================================================================

account_component_package!(
    ALLOWLIST_STORAGE_PACKAGE,
    "miden-standards-faucets-policies-transfer-allowlist-storage.masp"
);

static ALLOWED_ACCOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::transfer::allowlist::allowed_accounts",
    )
    .expect("storage slot name should be valid")
});

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`AllowlistStorage::NAME`], which mirrors the standards-side MASM module path.
const ALLOWLIST_STORAGE_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::allowlist::storage";

procedure_root!(
    ALLOWLIST_STORAGE_IS_ALLOWED,
    ALLOWLIST_STORAGE_LIBRARY_PATH,
    AllowlistStorage::IS_ALLOWED_PROC_NAME,
    AllowlistStorage::code()
);

/// Account component that installs the per-faucet allowlist and exposes the `is_allowed`
/// accessor.
///
/// The `allowed_accounts` map is read by the basic allowlist send and receive policies
/// ([`super::SendPolicy::with_basic_allowlist`], [`super::ReceivePolicy::with_basic_allowlist`])
/// and written by [`AllowlistManager`]. Install it once on a faucet that uses either policy, with
/// the initial set of allowed accounts.
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
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::transfer::allowlist";

    const IS_ALLOWED_PROC_NAME: &'static str = "is_allowed";

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

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOWLIST_STORAGE_PACKAGE.code
    }

    /// Returns the procedure root of the `is_allowed` call procedure exposed by this component.
    pub fn is_allowed_root() -> AccountProcedureRoot {
        *ALLOWLIST_STORAGE_IS_ALLOWED
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        ALLOWLIST_STORAGE_PACKAGE.metadata.clone()
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

impl From<AllowlistStorage> for AccountComponent {
    fn from(storage: AllowlistStorage) -> Self {
        let metadata = AllowlistStorage::component_metadata();

        AccountComponent::new(AllowlistStorage::code().clone(), vec![storage.into_slot()], metadata)
            .expect(
                "allowlist storage component should satisfy the requirements of a valid account component",
            )
    }
}
