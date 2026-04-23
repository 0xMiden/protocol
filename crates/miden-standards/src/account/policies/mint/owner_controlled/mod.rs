//! Owner-controlled mint policies.
//!
//! Each policy under this family is intended to be paired with a
//! [`crate::account::policies::mint::PolicyManager`] configured with
//! [`crate::account::policies::mint::PolicyAuthority::OwnerControlled`].

mod owner_only;

use miden_protocol::Word;
pub use owner_only::OwnerOnly;

// MINT OWNER-CONTROLLED CONFIG
// ================================================================================================

/// Initial configuration for an owner-controlled
/// [`crate::account::policies::mint::PolicyManager`].
///
/// Passed to [`crate::account::policies::mint::PolicyManager::owner_controlled`] to select
/// which policy is active when the faucet is first created. Future owner-controlled policies will
/// show up here as additional variants.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintOwnerControlledConfig {
    /// Active policy = [`OwnerOnly::root`] (mint gated by the account owner).
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
            Self::OwnerOnly => OwnerOnly::root(),
            Self::CustomInitialRoot(root) => root,
        }
    }
}
