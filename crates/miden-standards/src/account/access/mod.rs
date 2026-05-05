use alloc::vec;

use miden_protocol::account::{AccountComponent, AccountId};

pub mod ownable2step;
pub mod rbac;

/// Access control configuration for account components.
///
/// Each variant expands into the set of [`AccountComponent`]s that implement that access
/// control choice. Single-component variants like [`AccessControl::Ownable2Step`] expand
/// to one component; composite variants like [`AccessControl::Rbac`] expand to multiple
/// components in the order they must be installed (RBAC depends on
/// [`ownable2step::Ownable2Step`], so the latter is included alongside it).
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
/// AccountBuilder::new(init_seed).with_components(AccessControl::Rbac { owner });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControl {
    /// Two-step ownership transfer with the provided initial owner.
    Ownable2Step { owner: AccountId },
    /// Role-based access control. Includes [`Ownable2Step`] internally; the provided
    /// `owner` becomes the top-level RBAC authority (the account's owner).
    Rbac { owner: AccountId },
}

impl IntoIterator for AccessControl {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s implementing this access control configuration,
    /// in the order they must be installed on the account.
    fn into_iter(self) -> Self::IntoIter {
        match self {
            AccessControl::Ownable2Step { owner } => {
                vec![Ownable2Step::new(owner).into()].into_iter()
            },
            AccessControl::Rbac { owner } => {
                vec![Ownable2Step::new(owner).into(), RoleBasedAccessControl::empty().into()]
                    .into_iter()
            },
        }
    }
}

pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use rbac::RoleBasedAccessControl;
