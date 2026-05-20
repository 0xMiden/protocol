use alloc::vec;

use miden_protocol::account::{AccountComponent, AccountId, RoleSymbol};

use crate::auth_method::AuthMethod;

pub mod authority;
pub mod ownable2step;
pub mod rbac;

/// Access control configuration for account components.
///
/// - [`AccessControl::AuthControlled`] → [`Authority::AuthControlled`] (only). The setter gate
///   delegates to the auth component.
/// - [`AccessControl::Ownable2Step`] → [`Ownable2Step`] + [`Authority::OwnerControlled`]. The
///   setter gate enforces `sender == owner`.
/// - [`AccessControl::Rbac`] → [`Ownable2Step`] + [`RoleBasedAccessControl`] + an [`Authority`].
///   The `authority_role` field selects which authority kind is installed:
///   - `None` → [`Authority::OwnerControlled`] (the top-level owner gates `set_*` operations).
///   - `Some(role)` → [`Authority::RbacControlled { role }`] (any holder of `role` gates `set_*`
///     operations).
///
/// Note that the auth component is **not** yielded by [`IntoIterator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControl {
    /// The account's auth component is used for both transaction-level authentication
    /// and authority-gated setters.
    AuthControlled { auth: AuthMethod },
    /// Two-step ownership transfer with the provided initial owner. The setter gate enforces
    /// `sender == owner`.
    Ownable2Step { owner: AccountId, auth: AuthMethod },
    /// Role-based access control. Includes [`Ownable2Step`] internally. The provided `owner`
    /// becomes the top-level RBAC authority (the account's owner). `auth` governs the
    /// account's own transaction authentication only.
    ///
    /// `authority_role` controls which authority is installed alongside RBAC:
    /// - `None` (default) → [`Authority::OwnerControlled`]: the top-level `owner` is the sole
    ///   authority for `set_*` operations (`set_mint_policy`, `set_burn_policy`, metadata setters).
    ///   RBAC roles can still be granted and revoked but they do not directly gate the
    ///   authority-protected procedures.
    /// - `Some(role)` → [`Authority::RbacControlled { role }`]: any account holding `role` becomes
    ///   a valid authority for `set_*` operations. Role membership is managed through the standard
    ///   RBAC API on the [`RoleBasedAccessControl`] component.
    Rbac {
        owner: AccountId,
        authority_role: Option<RoleSymbol>,
        auth: AuthMethod,
    },
}

impl AccessControl {
    /// Returns the [`AuthMethod`] selected for the account's auth component.
    pub fn auth_method(&self) -> &AuthMethod {
        match self {
            AccessControl::AuthControlled { auth }
            | AccessControl::Ownable2Step { auth, .. }
            | AccessControl::Rbac { auth, .. } => auth,
        }
    }
}

impl IntoIterator for AccessControl {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AccessControl::AuthControlled { auth: _ } => {
                vec![Authority::AuthControlled.into()].into_iter()
            },
            AccessControl::Ownable2Step { owner, auth: _ } => {
                vec![Ownable2Step::new(owner).into(), Authority::OwnerControlled.into()].into_iter()
            },
            AccessControl::Rbac { owner, authority_role: None, auth: _ } => vec![
                Ownable2Step::new(owner).into(),
                RoleBasedAccessControl::empty().into(),
                Authority::OwnerControlled.into(),
            ]
            .into_iter(),
            AccessControl::Rbac {
                owner,
                authority_role: Some(role),
                auth: _,
            } => vec![
                Ownable2Step::new(owner).into(),
                RoleBasedAccessControl::empty().into(),
                Authority::RbacControlled { role }.into(),
            ]
            .into_iter(),
        }
    }
}

pub use authority::{Authority, AuthorityError};
pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use rbac::RoleBasedAccessControl;
