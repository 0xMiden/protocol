//! Mint policy components and the mint policy configuration enum used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;

mod allow_all;
mod owner_only;

pub use allow_all::MintAllowAll;
pub use owner_only::MintOwnerOnly;

// CONFIG
// ================================================================================================

/// Selects which mint policy is registered with a [`super::TokenPolicyManager`].
///
/// Pass to [`super::TokenPolicyManager::with_mint_policy`] together with a
/// [`super::PolicyRegistration`] to register the policy as either active or as a reserved
/// alternative.
#[derive(Debug, Clone, Copy, Default)]
pub enum MintPolicyConfig {
    /// Policy root = [`MintAllowAll::root`] (mint open to anyone).
    AllowAll,
    /// Policy root = [`MintOwnerOnly::root`] (mint gated by the account owner).
    #[default]
    OwnerOnly,
    /// Policy root = the provided word. The corresponding component must be installed by the
    /// caller separately; resolving this variant into built-in components yields an empty list.
    Custom(Word),
}

impl MintPolicyConfig {
    /// Returns the procedure root of the policy this variant resolves to.
    pub fn root(self) -> Word {
        match self {
            Self::AllowAll => MintAllowAll::root(),
            Self::OwnerOnly => MintOwnerOnly::root(),
            Self::Custom(root) => root,
        }
    }

    /// Returns the [`AccountComponent`]s that must accompany this mint policy variant.
    ///
    /// For [`Self::Custom`] this is empty — the caller installs whatever the chosen root
    /// requires.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        match self {
            Self::AllowAll => vec![MintAllowAll.into()],
            Self::OwnerOnly => vec![MintOwnerOnly.into()],
            Self::Custom(_) => Vec::new(),
        }
    }
}
