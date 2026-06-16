use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// PAUSABLE MANAGER COMPONENT
// ================================================================================================

account_component_code!(PAUSABLE_MANAGER_CODE, "access/pausable/manager.masl");

procedure_root!(
    PAUSABLE_MANAGER_PAUSE,
    PausableManager::NAME,
    PausableManager::PAUSE_PROC_NAME,
    PausableManager::code()
);

procedure_root!(
    PAUSABLE_MANAGER_UNPAUSE,
    PausableManager::NAME,
    PausableManager::UNPAUSE_PROC_NAME,
    PausableManager::code()
);

/// Account component exposing `pause` and `unpause` admin procedures, gated by the account-wide
/// [`crate::account::access::Authority`] component via `exec.authority::assert_authorized`.
///
/// `PausableManager` works uniformly with every standard access scheme:
/// - [`crate::account::access::Authority::AuthControlled`] — installed directly by
///   [`crate::account::faucets::create_user_fungible_faucet`]; gates pause / unpause via the
///   account's own auth component.
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
    pub const NAME: &'static str = "miden::standards::components::access::pausable::manager";

    pub const PAUSE_PROC_NAME: &'static str = "pause";
    pub const UNPAUSE_PROC_NAME: &'static str = "unpause";

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
}

impl From<PausableManager> for AccountComponent {
    fn from(_: PausableManager) -> Self {
        let metadata = AccountComponentMetadata::new(PausableManager::NAME).with_description(
            "PausableManager: pause / unpause admin procedures gated by the account-wide \
             Authority component. Requires the Pausable companion component for storage and the \
             Authority component for auth dispatch.",
        );

        AccountComponent::new(PausableManager::code().clone(), vec![], metadata).expect(
            "pausable manager component should satisfy the requirements of a valid account component",
        )
    }
}
