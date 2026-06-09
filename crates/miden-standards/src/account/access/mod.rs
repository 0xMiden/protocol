use alloc::collections::BTreeMap;
use alloc::vec;

use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot, RoleSymbol};

pub mod authority;
pub mod ownable2step;
pub mod pausable;
pub mod rbac;

/// Access control configuration for account components.
///
/// Each variant expands into the set of [`AccountComponent`]s that implement that access
/// control choice **plus** the matching [`Authority`] component. The [`Authority`] is
/// auto-yielded so callers don't need to remember to install it separately and so that the
/// authority discriminator stays in sync with the chosen access mode.
///
/// - [`AccessControl::AuthControlled`] yields just [`Authority::AuthControlled`].
/// - [`AccessControl::Ownable2Step`] yields [`Ownable2Step`] + [`Authority::OwnerControlled`].
/// - [`AccessControl::Rbac`] yields [`Ownable2Step`] + [`RoleBasedAccessControl`] +
///   [`Authority::RbacControlled`]. The `roles` map assigns a role to individual gated procedures
///   (keyed by procedure root); procedures without a mapping fall back to `default`
///   ([`DefaultAuthority::Owner`] or a default role).
///
/// Pass to
/// [`AccountBuilder::with_components`][miden_protocol::account::AccountBuilder::with_components]
/// to install the access control components on the account:
///
/// ```no_run
/// use std::collections::BTreeMap;
///
/// use miden_protocol::account::AccountBuilder;
/// use miden_standards::account::access::{AccessControl, DefaultAuthority};
/// # let owner: miden_protocol::account::AccountId = unimplemented!();
/// # let init_seed = [0u8; 32];
/// AccountBuilder::new(init_seed).with_components(AccessControl::Rbac {
///     owner,
///     roles: BTreeMap::new(),
///     default: DefaultAuthority::Owner,
/// });
/// ```
///
/// For accounts that don't use the [`AccessControl`] convenience but want to install the
/// [`Authority`] component directly, the [`Authority`] enum can be passed via
/// [`AccountBuilder::with_component`][miden_protocol::account::AccountBuilder::with_component].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControl {
    /// No external access control component is installed; access decisions are gated solely
    /// by the account's auth component.
    AuthControlled,
    /// Two-step ownership transfer with the provided initial owner. Authority for `set_*`
    /// operations is fixed to the registered owner.
    Ownable2Step { owner: AccountId },
    /// Role-based access control. Includes [`Ownable2Step`] internally; the provided `owner`
    /// becomes the top-level RBAC authority (the account's owner).
    Rbac {
        owner: AccountId,
        roles: BTreeMap<AccountProcedureRoot, RoleSymbol>,
        default: DefaultAuthority,
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
            AccessControl::Rbac { owner, roles, default } => vec![
                Ownable2Step::new(owner).into(),
                RoleBasedAccessControl::empty().into(),
                Authority::RbacControlled { roles, default }.into(),
            ]
            .into_iter(),
        }
    }
}

pub use authority::{Authority, AuthorityError, DefaultAuthority};
pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use pausable::{Pausable, PausableManager, PausableStorage};
pub use rbac::RoleBasedAccessControl;
