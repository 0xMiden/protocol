//! Mint policies and the mint policy manager.

use miden_protocol::Word;

mod allow_all;
mod manager;
mod owner_only;

pub use allow_all::MintAllowAll;
pub use manager::MintPolicyManager;
pub use owner_only::MintOwnerOnly;

// CONFIG
// ================================================================================================

/// Initial configuration for an owner-controlled [`MintPolicyManager`].
///
/// Passed to [`MintPolicyManager::owner_controlled`] to select which policy is active when the
/// faucet is first created. Only the chosen policy is registered as allowed by default; to permit
/// runtime switching to another policy, the caller must register it explicitly via
/// [`MintPolicyManager::with_allowed_policy`] and add the corresponding component.
///
/// Future owner-controlled mint policies will show up here as additional variants.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintOwnerControlledConfig {
    /// Active policy = [`MintOwnerOnly::root`] (mint gated by the account owner).
    #[default]
    OwnerOnly,
    /// Active policy = the provided root. Must be one of the allowed policy roots registered on
    /// the manager.
    CustomInitialRoot(Word),
}

impl MintOwnerControlledConfig {
    /// Resolves the config into the concrete policy root to install as the active mint policy.
    pub fn initial_policy_root(self) -> Word {
        match self {
            Self::OwnerOnly => MintOwnerOnly::root(),
            Self::CustomInitialRoot(root) => root,
        }
    }
}
