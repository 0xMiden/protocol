//! Burn policies and the burn policy manager.

use miden_protocol::Word;

mod allow_all;
mod manager;
mod owner_only;

pub use allow_all::BurnAllowAll;
pub use manager::BurnPolicyManager;
pub use owner_only::BurnOwnerOnly;

// CONFIG
// ================================================================================================

/// Initial configuration for an owner-controlled [`BurnPolicyManager`].
///
/// Passed to [`BurnPolicyManager::owner_controlled`] to select which policy is active when the
/// faucet is first created. Only the chosen policy is registered as allowed by default; to permit
/// runtime switching to another policy, the caller must register it explicitly via
/// [`BurnPolicyManager::with_allowed_policy`] and add the corresponding component.
#[derive(Debug, Clone, Copy, Default)]
pub enum BurnOwnerControlledConfig {
    /// Active policy = [`BurnAllowAll::root`] (burns open by default).
    #[default]
    AllowAll,
    /// Active policy = [`BurnOwnerOnly::root`] (burns locked to owner).
    OwnerOnly,
    /// Active policy = the provided root. Must be one of the allowed policy roots registered on
    /// the manager.
    CustomInitialRoot(Word),
}

impl BurnOwnerControlledConfig {
    /// Resolves the config into the concrete policy root to install as the active burn policy.
    pub fn initial_policy_root(self) -> Word {
        match self {
            Self::AllowAll => BurnAllowAll::root(),
            Self::OwnerOnly => BurnOwnerOnly::root(),
            Self::CustomInitialRoot(root) => root,
        }
    }
}
