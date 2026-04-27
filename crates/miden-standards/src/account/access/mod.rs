use miden_protocol::account::{AccountComponent, AccountId};

pub mod ownable2step;
pub mod role_based_access_control;

/// Access control configuration for account components that need a single top-level
/// authority.
///
/// This represents access control choices that can be expressed as a single account
/// component. Composite access control configurations (such as
/// [`role_based_access_control::RoleBasedAccessControl`], which depends on
/// [`ownable2step::Ownable2Step`]) are not represented here; build them via their own
/// constructors instead (e.g. `RoleBasedAccessControl::with_owner`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControl {
    /// Two-step ownership transfer with the provided initial owner.
    Ownable2Step { owner: AccountId },
}

impl From<AccessControl> for AccountComponent {
    fn from(access_control: AccessControl) -> Self {
        match access_control {
            AccessControl::Ownable2Step { owner } => Ownable2Step::new(owner).into(),
        }
    }
}

pub use ownable2step::{Ownable2Step, Ownable2StepError};
pub use role_based_access_control::{RoleBasedAccessControl, RoleInit};
