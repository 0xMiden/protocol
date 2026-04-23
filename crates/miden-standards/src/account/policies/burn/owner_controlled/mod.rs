//! Owner-controlled burn policies.
//!
//! Each policy under this family is intended to be paired with a
//! [`crate::account::policies::burn::PolicyManager`] configured with
//! [`crate::account::policies::burn::PolicyAuthority::OwnerControlled`].

mod owner_only;

use miden_protocol::Word;
pub use owner_only::OwnerOnly;

use crate::account::policies::burn::AllowAll;

// CONFIG
// ================================================================================================

/// Initial configuration for an owner-controlled
/// [`crate::account::policies::burn::PolicyManager`].
///
/// Passed to [`crate::account::policies::burn::PolicyManager::owner_controlled`] to select which
/// policy is active when the faucet is first created.
///
/// Note: owner-controlled burn managers register BOTH `owner_only` and `allow_all` as allowed
/// policies so the owner can switch between them at runtime via `set_burn_policy`. This enum only
/// selects the **initial active** policy.
#[derive(Debug, Clone, Copy, Default)]
pub enum Config {
    /// Active policy = [`AllowAll::root`] (burns open by default).
    #[default]
    AllowAll,
    /// Active policy = [`OwnerOnly::root`] (burns locked to owner).
    OwnerOnly,
    /// Active policy = the provided root. Must be one of the allowed policy roots registered on
    /// the manager.
    CustomInitialRoot(Word),
}

impl Config {
    /// Resolves the config into the concrete policy root to install as the active burn policy.
    pub fn initial_policy_root(self) -> Word {
        match self {
            Self::AllowAll => AllowAll::root(),
            Self::OwnerOnly => OwnerOnly::root(),
            Self::CustomInitialRoot(root) => root,
        }
    }
}
