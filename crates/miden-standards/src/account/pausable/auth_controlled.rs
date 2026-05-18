use alloc::vec;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot, AccountType};

use crate::account::account_component_code;
use crate::procedure_root;

account_component_code!(PAUSABLE_AUTH_CONTROLLED_CODE, "utils/pausable/auth_controlled.masl");

// PAUSABLE AUTH-CONTROLLED ADMIN COMPONENT
// ================================================================================================

procedure_root!(
    PAUSABLE_AUTH_CONTROLLED_PAUSE,
    PausableAuthControlled::NAME,
    PausableAuthControlled::PAUSE_PROC_NAME,
    PausableAuthControlled::code()
);

procedure_root!(
    PAUSABLE_AUTH_CONTROLLED_UNPAUSE,
    PausableAuthControlled::NAME,
    PausableAuthControlled::UNPAUSE_PROC_NAME,
    PausableAuthControlled::code()
);

procedure_root!(
    PAUSABLE_AUTH_CONTROLLED_IS_PAUSED,
    PausableAuthControlled::NAME,
    PausableAuthControlled::IS_PAUSED_PROC_NAME,
    PausableAuthControlled::code()
);

/// Account component that exposes `pause` / `unpause` / `is_paused` as `Invocation: call`
/// procedures with no explicit authorization check.
///
/// Authorization is delegated entirely to the account's own auth component (e.g.
/// `AuthSingleSig`, `AuthMultisig`, `NoAuth`, `AuthNetworkAccount`) — whoever the account's
/// auth scheme lets sign a transaction can call these procedures. Use this variant when
/// pause/unpause should be available to anyone the account's standard auth flow accepts,
/// paired with [`crate::account::access::AccessControl::AuthControlled`].
///
/// For owner- or role-gated variants see [`super::PausableOwnerControlled`] and
/// [`super::PausableRoleControlled`].
///
/// Companion components required:
/// - [`crate::account::policies::transfer::BasicPausable`] (or another component that installs the
///   [`crate::account::pausable::PausableStorage`] slot) — provides the `is_paused` storage slot
///   that pause / unpause write to.
#[derive(Debug, Clone, Copy, Default)]
pub struct PausableAuthControlled;

impl PausableAuthControlled {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::utils::pausable::auth_controlled";

    pub const PAUSE_PROC_NAME: &'static str = "pause";
    pub const UNPAUSE_PROC_NAME: &'static str = "unpause";
    pub const IS_PAUSED_PROC_NAME: &'static str = "is_paused";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PAUSABLE_AUTH_CONTROLLED_CODE
    }

    /// Returns the procedure root of the `pause` procedure exposed by this component.
    pub fn pause_root() -> AccountProcedureRoot {
        *PAUSABLE_AUTH_CONTROLLED_PAUSE
    }

    /// Returns the procedure root of the `unpause` procedure exposed by this component.
    pub fn unpause_root() -> AccountProcedureRoot {
        *PAUSABLE_AUTH_CONTROLLED_UNPAUSE
    }

    /// Returns the procedure root of the `is_paused` procedure exposed by this component.
    pub fn is_paused_root() -> AccountProcedureRoot {
        *PAUSABLE_AUTH_CONTROLLED_IS_PAUSED
    }

    /// Returns the [`AccountComponentMetadata`] describing this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME, AccountType::all()).with_description(
            "Auth-controlled pause admin: exposes `pausable::pause` / `unpause` / `is_paused` \
             as call procedures with no explicit auth gate (the account's own auth component \
             is the only authorization).",
        )
    }
}

impl From<PausableAuthControlled> for AccountComponent {
    fn from(_: PausableAuthControlled) -> Self {
        let metadata = PausableAuthControlled::component_metadata();
        AccountComponent::new(PausableAuthControlled::code().clone(), vec![], metadata).expect(
            "auth-controlled pausable admin component should satisfy the requirements of a valid account component",
        )
    }
}
