use alloc::vec;
use alloc::vec::Vec;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControl {
    /// Two-step ownership transfer with the provided initial owner.
    Ownable2Step { owner: AccountId },
    /// Role-based access control. Includes [`Ownable2Step`] internally; the provided
    /// `owner` becomes the top-level RBAC authority (the account's owner).
    Rbac { owner: AccountId },
}

impl AccessControl {
    /// Returns the [`AccountComponent`]s implementing this access control configuration,
    /// in the order they must be installed on the account.
    pub fn into_components(self) -> Vec<AccountComponent> {
        self.into()
    }
}

impl From<AccessControl> for Vec<AccountComponent> {
    fn from(access_control: AccessControl) -> Self {
        match access_control {
            AccessControl::Ownable2Step { owner } => vec![Ownable2Step::new(owner).into()],
            AccessControl::Rbac { owner } => RoleBasedAccessControl::with_owner(owner),
        }
    }
}

pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use rbac::{RoleBasedAccessControl, RoleConfig};
