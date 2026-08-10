use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// UPGRADE MANAGER COMPONENT
// ================================================================================================

account_component_code!(UPGRADE_MANAGER_CODE, "miden-standards-upgrade-manager.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`UpgradeManager::NAME`],
/// which mirrors the standards-side MASM module path.
const UPGRADE_MANAGER_LIBRARY_PATH: &str = "miden::standards::components::upgrade::manager";

procedure_root!(
    UPGRADE_MANAGER_UPGRADE,
    UPGRADE_MANAGER_LIBRARY_PATH,
    UpgradeManager::UPGRADE_PROC_NAME,
    UpgradeManager::code()
);

/// Account component exposing an `upgrade` admin procedure, gated by the account-wide
/// [`crate::account::access::Authority`] component via `exec.authority::assert_authorized`.
///
/// The procedure wraps the protocol `native_account::upgrade` kernel procedure, letting an account
/// record the commitments describing an upgrade of its own code and storage. It is currently a
/// no-op beyond storing the two commitments in kernel memory; the actual upgrade application is not
/// yet implemented and the commitment formats are not yet defined. `assert_authorized` is the hook
/// where any stronger authorization gate would live once upgrades are enabled.
///
/// `UpgradeManager` works with every standard access scheme that installs an [`Authority`]
/// component.
///
/// Companion component required:
/// - [`Authority`].
///
/// [`Authority`]: crate::account::access::Authority
#[derive(Debug, Clone, Copy, Default)]
pub struct UpgradeManager;

impl UpgradeManager {
    /// The name of the component.
    const NAME: &'static str = "miden::standards::upgrade::manager";

    const UPGRADE_PROC_NAME: &'static str = "upgrade";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &UPGRADE_MANAGER_CODE
    }

    /// Returns the procedure root of the `upgrade` procedure exposed by this component.
    pub fn upgrade_root() -> AccountProcedureRoot {
        *UPGRADE_MANAGER_UPGRADE
    }
}

impl From<UpgradeManager> for AccountComponent {
    fn from(_: UpgradeManager) -> Self {
        let metadata = AccountComponentMetadata::new(UpgradeManager::NAME)
            .with_description("Code and storage upgrades for accounts.");

        AccountComponent::new(UpgradeManager::code().clone(), vec![], metadata).expect(
            "upgrade manager component should satisfy the requirements of a valid account component",
        )
    }
}
