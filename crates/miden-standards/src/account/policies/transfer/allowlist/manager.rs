use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::{account_component_code, package_metadata};
use crate::procedure_root;

account_component_code!(
    ALLOWLIST_MANAGER_CODE,
    "miden-standards-faucets-policies-transfer-allowlist-manager.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`AllowlistManager::NAME`], which mirrors the standards-side MASM module path.
const ALLOWLIST_MANAGER_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::allowlist::manager";

procedure_root!(
    ALLOWLIST_MANAGER_ALLOW_ACCOUNT,
    ALLOWLIST_MANAGER_LIBRARY_PATH,
    AllowlistManager::ALLOW_ACCOUNT_PROC_NAME,
    AllowlistManager::code()
);

procedure_root!(
    ALLOWLIST_MANAGER_DISALLOW_ACCOUNT,
    ALLOWLIST_MANAGER_LIBRARY_PATH,
    AllowlistManager::DISALLOW_ACCOUNT_PROC_NAME,
    AllowlistManager::code()
);

/// Account component that exposes `allow_account` and `disallow_account` admin procedures gated
/// by the account-wide [`crate::account::access::Authority`] component via
/// `exec.authority::assert_authorized`.
///
/// `AllowlistManager` works uniformly with every standard access scheme:
/// - [`crate::account::access::Authority::AuthControlled`] — gates the admin procedures via the
///   account's own auth component.
/// - [`crate::account::access::AccessControl::Ownable2Step`] →
///   [`crate::account::access::Authority::OwnerControlled`] requires the Ownable2Step owner.
/// - [`crate::account::access::AccessControl::Rbac`] →
///   [`crate::account::access::Authority::RbacControlled`] resolves a role per procedure. Map both
///   [`Self::allow_account_root`] and [`Self::disallow_account_root`] to the same role symbol (e.g.
///   an `ALLOWLISTER` role) so a single role gates both operations, or map them to distinct roles.
///
/// Companion components required:
/// - [`crate::account::access::Authority`] — provides the mode-aware auth dispatch.
/// - A component that installs the `allowed_accounts` storage slot — typically
///   [`crate::account::policies::BasicAllowlist`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowlistManager;

impl AllowlistManager {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::faucets::policies::transfer::allowlist::manager";

    const ALLOW_ACCOUNT_PROC_NAME: &'static str = "allow_account";
    const DISALLOW_ACCOUNT_PROC_NAME: &'static str = "disallow_account";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ALLOWLIST_MANAGER_CODE
    }

    /// Returns the procedure root of the `allow_account` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn allow_account_root() -> AccountProcedureRoot {
        *ALLOWLIST_MANAGER_ALLOW_ACCOUNT
    }

    /// Returns the procedure root of the `disallow_account` procedure exposed by this component.
    ///
    /// Use it to key the [`crate::account::access::Authority::RbacControlled`] role map.
    pub fn disallow_account_root() -> AccountProcedureRoot {
        *ALLOWLIST_MANAGER_DISALLOW_ACCOUNT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl From<AllowlistManager> for AccountComponent {
    fn from(_: AllowlistManager) -> Self {
        let metadata = AllowlistManager::component_metadata();
        AccountComponent::new(AllowlistManager::code().clone(), vec![], metadata)
            .expect("authority-gated allowlist admin component should be valid")
    }
}
