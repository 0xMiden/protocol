use alloc::vec;

use miden_protocol::account::{AccountComponent, AccountId, RoleSymbol};

use crate::auth_method::AuthMethod;

pub mod authority;
pub mod ownable2step;
pub mod rbac;

/// Access control configuration for account components.
///
/// Bundles two related concerns into a single declarative value:
///
/// 1. **Account-level authentication** ([`AuthMethod`]) — selects the auth component that gates
///    every transaction executed against the account (signature, network-account allowlist,
///    nonce-only, ...).
/// 2. **Setter access gate** — selects the [`Authority`] policy consulted by `set_*` procedures
///    such as `set_max_supply`, `set_mint_policy`, and the token metadata setters. Each variant of
///    this enum picks a different gate; see the variants below.
///
/// Each variant carries an `auth: AuthMethod` field for concern (1). The variant itself
/// (`AuthControlled` / `Ownable2Step` / `Rbac`) drives concern (2). In `AuthControlled` the two
/// concerns coincide: the auth component **is** the setter gate, so the auth component must
/// authenticate every authority-gated setter (factories enforce this; see
/// [`create_fungible_faucet`][crate::account::faucets::create_fungible_faucet]).
///
/// The variants expand into:
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
/// Note that the auth component is **not** yielded by [`IntoIterator`]; it is constructed
/// separately by factory functions
/// ([`create_fungible_faucet`][crate::account::faucets::create_fungible_faucet])
/// from [`Self::auth_method`] and installed via
/// [`AccountBuilder::with_auth_component`][miden_protocol::account::AccountBuilder::with_auth_component].
/// The iterator only yields the setter-gate components.
///
/// ```no_run
/// use miden_protocol::account::AccountBuilder;
/// use miden_standards::AuthMethod;
/// use miden_standards::account::access::AccessControl;
/// # let owner: miden_protocol::account::AccountId = unimplemented!();
/// # let init_seed = [0u8; 32];
/// AccountBuilder::new(init_seed).with_components(AccessControl::Rbac {
///     owner,
///     authority_role: None,
///     auth: AuthMethod::NoAuth,
/// });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControl {
    /// No external setter-gate component is installed; the account's auth component is the
    /// sole gate for both transaction-level authentication and authority-gated setters.
    ///
    /// Because `Authority::AuthControlled` makes `assert_authorized` a no-op, the auth
    /// component **must** authenticate every authority-gated setter root for setters to be
    /// safe. Factories that build accounts under this variant reject auth methods that
    /// cannot meet that invariant (for example,
    /// [`create_fungible_faucet`][crate::account::faucets::create_fungible_faucet] rejects
    /// [`AuthMethod::NoAuth`]).
    AuthControlled { auth: AuthMethod },
    /// Two-step ownership transfer with the provided initial owner. The setter gate enforces
    /// `sender == owner`; the auth component on `auth` only governs the faucet's own
    /// transaction authentication.
    Ownable2Step { owner: AccountId, auth: AuthMethod },
    /// Role-based access control. Includes [`Ownable2Step`] internally; the provided `owner`
    /// becomes the top-level RBAC authority (the account's owner). `auth` governs the
    /// account's own transaction authentication only.
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
        auth: AuthMethod,
    },
}

impl AccessControl {
    /// Returns the [`AuthMethod`] selected for the account's auth component. Factories use
    /// this to construct the auth component before installing the setter-gate components
    /// yielded by [`IntoIterator`].
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

    /// Yields the [`AccountComponent`]s implementing the **setter-gate** half of this access
    /// control configuration. The auth component (concern (1) in the type-level docs) is
    /// **not** yielded; callers obtain it from [`Self::auth_method`] and install it
    /// separately via
    /// [`AccountBuilder::with_auth_component`][miden_protocol::account::AccountBuilder::with_auth_component].
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
