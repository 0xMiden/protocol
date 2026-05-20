use alloc::vec;

use miden_protocol::account::{AccountComponent, AccountId, RoleSymbol};

pub mod authority;
pub mod ownable2step;
pub mod rbac;

/// Access control configuration for account components.
///
/// - [`AccessControl::AuthControlled`] yields just [`Authority::AuthControlled`].
/// - [`AccessControl::Ownable2Step`] yields [`Ownable2Step`] + [`Authority::OwnerControlled`].
/// - [`AccessControl::Rbac`] yields [`Ownable2Step`] + [`RoleBasedAccessControl`] + an
///   [`Authority`]. The `authority_role` field selects which authority kind is installed:
///   - `None` → [`Authority::OwnerControlled`] (the top-level owner gates `set_*` operations).
///   - `Some(role)` → [`Authority::RbacControlled { role }`] (any holder of `role` gates `set_*`
///     operations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControl {
    /// No external access control component is installed; access decisions are gated solely
    /// by the account's auth component.
    AuthControlled,
    /// Two-step ownership transfer with the provided initial owner. Authority for `set_*`
    /// operations is fixed to the registered owner.
    Ownable2Step { owner: AccountId },
    /// Role-based access control. Includes [`Ownable2Step`] internally, the provided `owner`
    /// becomes the top-level RBAC authority (the account's owner).
    ///
    /// `authority_role` controls which authority is installed alongside RBAC:
    /// - `None` (default) → [`Authority::OwnerControlled`]: the top-level `owner` is the sole
    ///   authority for `set_*` operations (`set_mint_policy`, `set_burn_policy`, metadata setters).
    ///   RBAC roles can still be granted/revoked but they do not directly gate the
    ///   authority-protected procedures.
    /// - `Some(role)` → [`Authority::RbacControlled { role }`]: any account holding `role` becomes
    ///   a valid authority for `set_*` operations. Role membership is managed through the standard
    ///   RBAC API on the [`RoleBasedAccessControl`] component.
    Rbac {
        owner: AccountId,
        authority_role: Option<RoleSymbol>,
    },
}

impl IntoIterator for AccessControl {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this access control configuration, in the
    /// order they must be installed on the account. The matching [`Authority`] component is
    /// always included.
    fn into_iter(self) -> Self::IntoIter {
        match self {
            AccessControl::AuthControlled => vec![Authority::AuthControlled.into()].into_iter(),
            AccessControl::Ownable2Step { owner } => {
                vec![Ownable2Step::new(owner).into(), Authority::OwnerControlled.into()].into_iter()
            },
            AccessControl::Rbac { owner, authority_role: None } => vec![
                Ownable2Step::new(owner).into(),
                RoleBasedAccessControl::empty().into(),
                Authority::OwnerControlled.into(),
            ]
            .into_iter(),
            AccessControl::Rbac { owner, authority_role: Some(role) } => vec![
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
