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

pub use manager::BlocklistManager;

// BLOCKED ACCOUNTS STORAGE
// ================================================================================================

account_component_package!(
    BLOCKLIST_STORAGE_PACKAGE,
    "miden-standards-faucets-policies-transfer-blocklist-storage.masp"
);

static BLOCKED_ACCOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::transfer::blocklist::blocked_accounts",
    )
    .expect("storage slot name should be valid")
});

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`BlocklistStorage::NAME`], which mirrors the standards-side MASM module path.
const BLOCKLIST_STORAGE_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::blocklist::storage";

procedure_root!(
    BLOCKLIST_STORAGE_IS_BLOCKED,
    BLOCKLIST_STORAGE_LIBRARY_PATH,
    BlocklistStorage::IS_BLOCKED_PROC_NAME,
    BlocklistStorage::code()
);

/// Account component that installs the per-faucet blocklist and exposes the `is_blocked`
/// accessor.
///
/// The `blocked_accounts` map is read by the basic blocklist send and receive policies
/// ([`super::SendPolicy::with_basic_blocklist`], [`super::ReceivePolicy::with_basic_blocklist`])
/// and written by [`BlocklistManager`]. Install it once on a faucet that uses either policy, with
/// the initial set of blocked accounts.
///
/// The low-level `block_account` / `unblock_account` / `is_blocked` / `assert_not_blocked`
/// procedures live in the standards library at
/// `miden::standards::faucets::policies::transfer::blocklist` as `Invocation: exec` helpers —
/// they perform no authorization and must be wrapped by an auth-checking admin component (see
/// [`BlocklistManager`]) before being exposed on a faucet.
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
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::transfer::blocklist";

    const IS_BLOCKED_PROC_NAME: &'static str = "is_blocked";

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

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BLOCKLIST_STORAGE_PACKAGE.code
    }

    /// Returns the procedure root of the `is_blocked` call procedure exposed by this component.
    pub fn is_blocked_root() -> AccountProcedureRoot {
        *BLOCKLIST_STORAGE_IS_BLOCKED
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        BLOCKLIST_STORAGE_PACKAGE.metadata.clone()
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

impl From<BlocklistStorage> for AccountComponent {
    fn from(storage: BlocklistStorage) -> Self {
        let metadata = BlocklistStorage::component_metadata();

        AccountComponent::new(BlocklistStorage::code().clone(), vec![storage.into_slot()], metadata)
            .expect(
                "blocklist storage component should satisfy the requirements of a valid account component",
            )
    }
}
