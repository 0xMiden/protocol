use miden_protocol::account::{AccountComponent, AccountId};

pub mod ownable2step;
pub mod role_based_access_control;

/// Access control configuration for account components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControl {
    /// Uses two-step ownership transfer with the provided initial owner.
    Ownable2Step { owner: AccountId },
    /// Uses role-based access control with the provided initial admin.
    RoleBasedAccessControl { admin: AccountId },
}

impl From<AccessControl> for AccountComponent {
    fn from(access_control: AccessControl) -> Self {
        match access_control {
            AccessControl::Ownable2Step { owner } => Ownable2Step::new(owner).into(),
            AccessControl::RoleBasedAccessControl { admin } => {
                RoleBasedAccessControl::new(admin).into()
            },
        }
    }
}

pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use role_based_access_control::{RoleBasedAccessControl, RoleInit};
