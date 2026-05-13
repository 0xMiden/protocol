use alloc::vec;

use miden_protocol::account::{AccountComponent, AccountId, RoleSymbol};

use crate::AuthMethod;

pub mod authority;
pub mod ownable2step;
pub mod rbac;

/// Access control configuration for account components.
///
/// Each variant expands into the set of [`AccountComponent`]s that implement that access
/// control choice **plus** the matching [`Authority`] component. The [`Authority`] is
/// auto-yielded so callers don't need to remember to install it separately and so that the
/// authority discriminator stays in sync with the chosen access mode.
///
/// - [`AccessControl::AuthControlled`] yields just [`Authority::AuthControlled`]. The supplied
///   [`AuthMethod`] is the only gate on `set_*` procedures and is installed by the constructor on
///   the account's auth component.
/// - [`AccessControl::Ownable2Step`] yields [`Ownable2Step`] + [`Authority::OwnerControlled`].
///   Gating happens via `assert_sender_is_owner`, so the account's own auth component is
///   [`AuthMethod::NoAuth`] (state changes are implicitly authorized by the owner's call).
/// - [`AccessControl::Rbac`] yields [`Ownable2Step`] + [`RoleBasedAccessControl`] + an
///   [`Authority`]. The `authority_role` field selects which authority kind is installed:
///   - `None` → [`Authority::OwnerControlled`] (the top-level owner gates `set_*` operations).
///   - `Some(role)` → [`Authority::RbacControlled { role }`] (any holder of `role` gates `set_*`
///     operations).
///
///   As with `Ownable2Step`, the account's own auth component is [`AuthMethod::NoAuth`] because
///   gating happens at the access-component level.
///
/// Pass to
/// [`AccountBuilder::with_components`][miden_protocol::account::AccountBuilder::with_components]
/// to install the access control components on the account:
///
/// ```no_run
/// use miden_protocol::account::AccountBuilder;
/// use miden_standards::account::access::AccessControl;
/// # let owner: miden_protocol::account::AccountId = unimplemented!();
/// # let init_seed = [0u8; 32];
/// AccountBuilder::new(init_seed)
///     .with_components(AccessControl::Rbac { owner, authority_role: None });
/// ```
///
/// For accounts that don't use the [`AccessControl`] convenience but want to install the
/// [`Authority`] component directly, the [`Authority`] enum can be passed via
/// [`AccountBuilder::with_component`][miden_protocol::account::AccountBuilder::with_component].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControl {
    /// No external access control component is installed; access decisions are gated solely
    /// by the account's auth component.
    ///
    /// - `Some(auth)`: the supplied [`AuthMethod`] is installed as the account's auth component
    ///   (used by [`create_fungible_faucet`][crate::account::faucets::create_fungible_faucet]).
    /// - `None`: the caller installs the auth component separately. This variant then only
    ///   contributes [`Authority::AuthControlled`] via [`IntoIterator`].
    AuthControlled { auth: Option<AuthMethod> },
    /// Two-step ownership transfer with the provided initial owner. Authority for `set_*`
    /// operations is fixed to the registered owner. The account's own auth component is
    /// [`AuthMethod::NoAuth`] because the owner's call already authorized the state change.
    Ownable2Step { owner: AccountId },
    /// Role-based access control. Includes [`Ownable2Step`] internally; the provided `owner`
    /// becomes the top-level RBAC authority (the account's owner). The account's own auth
    /// component is [`AuthMethod::NoAuth`] because gating happens via the role check.
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

impl AccessControl {
    /// Returns the [`AuthMethod`] that should be installed on the account's auth component, or
    /// `None` when the caller is expected to install it separately.
    ///
    /// - [`AccessControl::AuthControlled`] with `Some(auth)` → returns `Some(auth)`; the caller
    ///   should install it (this is the only gate on `set_*` procedures).
    /// - [`AccessControl::AuthControlled`] with `None` → returns `None`; the caller installs the
    ///   auth component separately.
    /// - [`AccessControl::Ownable2Step`] / [`AccessControl::Rbac`] → returns
    ///   `Some(AuthMethod::NoAuth)`; gating is performed by the access components via
    ///   `assert_authorized`, so the account's own auth is a rubber stamp on state changes.
    pub fn auth_method(&self) -> Option<AuthMethod> {
        match self {
            Self::AuthControlled { auth } => auth.clone(),
            Self::Ownable2Step { .. } | Self::Rbac { .. } => Some(AuthMethod::NoAuth),
        }
    }
}

impl IntoIterator for AccessControl {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the access [`AccountComponent`]s (Ownable2Step, RBAC, Authority) implementing this
    /// access control configuration, in the order they must be installed on the account.
    ///
    /// The auth component is **not** yielded here; install it separately via
    /// [`AccountBuilder::with_auth_component`][miden_protocol::account::AccountBuilder::with_auth_component]
    /// using the method returned by [`AccessControl::auth_method`].
    fn into_iter(self) -> Self::IntoIter {
        match self {
            AccessControl::AuthControlled { .. } => {
                vec![Authority::AuthControlled.into()].into_iter()
            },
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
