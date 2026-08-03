use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

account_component_code!(
    BLOCKLIST_MANAGER_CODE,
    "miden-standards-faucets-policies-transfer-blocklist-manager.masp"
);

procedure_root!(
    BLOCKLIST_MANAGER_BLOCK_ACCOUNT,
    BlocklistManager::NAME,
    BlocklistManager::BLOCK_ACCOUNT_PROC_NAME,
    BlocklistManager::code()
);

procedure_root!(
    BLOCKLIST_MANAGER_UNBLOCK_ACCOUNT,
    BlocklistManager::NAME,
    BlocklistManager::UNBLOCK_ACCOUNT_PROC_NAME,
    BlocklistManager::code()
);

/// Account component that exposes `block_account` and `unblock_account` admin procedures gated
/// by the account-wide [`crate::account::access::Authority`] component via
/// `exec.authority::assert_authorized`.
///
/// `BlocklistManager` works uniformly with every standard access scheme:
/// - [`crate::account::access::Authority::AuthControlled`] — gates the admin procedures via the
///   account's own auth component.
/// - [`crate::account::access::AccessControl::Ownable2Step`] →
///   [`crate::account::access::Authority::OwnerControlled`] requires the Ownable2Step owner.
/// - [`crate::account::access::AccessControl::Rbac`] →
///   [`crate::account::access::Authority::RbacControlled`] resolves a role per procedure. Map both
///   [`Self::block_account_root`] and [`Self::unblock_account_root`] to the same role symbol (e.g.
///   a `BLOCKLISTER` role) so a single role gates both operations, or map them to distinct roles.
///
/// Companion components required:
/// - [`crate::account::access::Authority`] — provides the mode-aware auth dispatch.
/// - A component that installs the `blocked_accounts` storage slot — typically
///   [`crate::account::policies::BasicBlocklist`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BlocklistManager;

impl BlocklistManager {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::blocklist::manager";

    const BLOCK_ACCOUNT_PROC_NAME: &'static str = "block_account";
    const UNBLOCK_ACCOUNT_PROC_NAME: &'static str = "unblock_account";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BLOCKLIST_MANAGER_CODE
    }

    /// Returns the procedure root of the `block_account` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn block_account_root() -> AccountProcedureRoot {
        *BLOCKLIST_MANAGER_BLOCK_ACCOUNT
    }

    /// Returns the procedure root of the `unblock_account` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn unblock_account_root() -> AccountProcedureRoot {
        *BLOCKLIST_MANAGER_UNBLOCK_ACCOUNT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME).with_description(
            "Authority-gated blocklist admin: wraps `blocklist::block_account` / \
             `unblock_account` with the account-wide Authority component.",
        )
    }
}

impl From<BlocklistManager> for AccountComponent {
    fn from(_: BlocklistManager) -> Self {
        let metadata = BlocklistManager::component_metadata();
        AccountComponent::new(BlocklistManager::code().clone(), vec![], metadata)
            .expect("authority-gated blocklist admin component should be valid")
    }
}
