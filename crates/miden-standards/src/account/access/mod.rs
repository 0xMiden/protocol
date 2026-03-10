use miden_protocol::account::{AccountComponent, AccountId};

pub mod ownable2step;

/// Access control configuration for account components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControl {
    /// Uses two-step ownership transfer with the provided initial owner.
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
