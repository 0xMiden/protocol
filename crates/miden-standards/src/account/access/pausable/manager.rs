use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::{account_component_code, package_metadata};
use crate::procedure_root;

// PAUSABLE MANAGER COMPONENT
// ================================================================================================

account_component_code!(PAUSABLE_MANAGER_CODE, "miden-standards-access-pausable-manager.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`PausableManager::NAME`], which mirrors the standards-side MASM module path.
const PAUSABLE_MANAGER_LIBRARY_PATH: &str =
    "miden::standards::components::access::pausable::manager";

procedure_root!(
    PAUSABLE_MANAGER_PAUSE,
    PAUSABLE_MANAGER_LIBRARY_PATH,
    PausableManager::PAUSE_PROC_NAME,
    PausableManager::code()
);

procedure_root!(
    PAUSABLE_MANAGER_UNPAUSE,
    PAUSABLE_MANAGER_LIBRARY_PATH,
    PausableManager::UNPAUSE_PROC_NAME,
    PausableManager::code()
);

/// Account component exposing `pause` and `unpause` admin procedures, gated by the account-wide
/// [`crate::account::access::Authority`] component via `exec.authority::assert_authorized`.
///
/// `PausableManager` works uniformly with every standard access scheme:
/// - [`crate::account::access::Authority::AuthControlled`] — installed directly by the user-account
///   faucet factories (e.g. [`crate::account::faucets::create_singlesig_user_fungible_faucet`]);
///   gates pause / unpause via the account's own auth component.
/// - [`crate::account::access::AccessControl::Ownable2Step`] →
///   [`crate::account::access::Authority::OwnerControlled`] requires the Ownable2Step owner.
/// - [`crate::account::access::AccessControl::Rbac`] →
///   [`crate::account::access::Authority::RbacControlled`] for roles per procedure.
///
/// Companion components required:
/// - [`crate::account::access::Authority`] — installed automatically by the
///   [`crate::account::access::AccessControl`] enum (or directly by user-faucet factories).
/// - [`super::Pausable`] — provides the `is_paused` storage slot that pause / unpause write to.
#[derive(Debug, Clone, Copy, Default)]
pub struct PausableManager;

impl PausableManager {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::access::pausable::manager";

    const PAUSE_PROC_NAME: &'static str = "pause";
    const UNPAUSE_PROC_NAME: &'static str = "unpause";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PAUSABLE_MANAGER_CODE
    }

    /// Returns the procedure root of the `pause` procedure exposed by this component.
    pub fn pause_root() -> AccountProcedureRoot {
        *PAUSABLE_MANAGER_PAUSE
    }

    /// Returns the procedure root of the `unpause` procedure exposed by this component.
    pub fn unpause_root() -> AccountProcedureRoot {
        *PAUSABLE_MANAGER_UNPAUSE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl From<PausableManager> for AccountComponent {
    fn from(_: PausableManager) -> Self {
        let metadata = PausableManager::component_metadata();

        AccountComponent::new(PausableManager::code().clone(), vec![], metadata).expect(
            "pausable manager component should satisfy the requirements of a valid account component",
        )
    }
}
