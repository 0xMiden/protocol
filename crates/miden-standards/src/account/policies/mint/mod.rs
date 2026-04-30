//! Mint policy components and the mint policy configuration enum used by
//! [`super::TokenPolicyManager`].

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;

mod allow_all;
mod owner_only;

pub use allow_all::MintAllowAll;
pub use owner_only::MintOwnerOnly;

// CONFIG
// ================================================================================================

/// Selects which mint policy is active when the [`super::TokenPolicyManager`] is first installed.
///
/// Only the chosen policy is registered as allowed by default; runtime switching to another policy
/// requires explicit opt-in via [`super::TokenPolicyManager::with_allowed_mint_policy`] plus
/// installing the matching policy component.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintPolicyConfig {
    /// Active policy = [`MintAllowAll::root`] (mint open to anyone).
    AllowAll,
    /// Active policy = [`MintOwnerOnly::root`] (mint gated by the account owner).
    #[default]
    OwnerOnly,
    /// Active policy = the provided root. The corresponding component must be installed by the
    /// caller separately; resolving this variant into a built-in component panics because there
    /// is no library known to this enum.
    Custom(Word),
}

impl MintPolicyConfig {
    /// Returns the procedure root of the active policy this config resolves to.
    pub fn root(self) -> Word {
        match self {
            Self::AllowAll => MintAllowAll::root(),
            Self::OwnerOnly => MintOwnerOnly::root(),
            Self::Custom(root) => root,
        }
    }

    /// Returns the [`AccountComponent`] corresponding to the active policy, or [`None`] for
    /// [`Self::Custom`] — custom policies must be installed by the caller directly.
    pub(crate) fn into_component(self) -> Option<AccountComponent> {
        match self {
            Self::AllowAll => Some(MintAllowAll.into()),
            Self::OwnerOnly => Some(MintOwnerOnly.into()),
            Self::Custom(_) => None,
        }
    }
}
