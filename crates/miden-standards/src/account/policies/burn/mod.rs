//! Burn policy components and the burn policy configuration enum used by
//! [`super::TokenPolicyManager`].

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;

mod allow_all;
mod owner_only;

pub use allow_all::BurnAllowAll;
pub use owner_only::BurnOwnerOnly;

// CONFIG
// ================================================================================================

/// Selects which burn policy is active when the [`super::TokenPolicyManager`] is first installed.
///
/// Only the chosen policy is registered as allowed by default; runtime switching to another policy
/// requires explicit opt-in via [`super::TokenPolicyManager::with_allowed_burn_policy`] plus
/// installing the matching policy component.
#[derive(Debug, Clone, Copy, Default)]
pub enum BurnPolicyConfig {
    /// Active policy = [`BurnAllowAll::root`] (burns open to anyone).
    #[default]
    AllowAll,
    /// Active policy = [`BurnOwnerOnly::root`] (burns gated by the account owner).
    OwnerOnly,
    /// Active policy = the provided root. The corresponding component must be installed by the
    /// caller separately; converting this variant via
    /// [`BurnPolicyConfig::into_component`] panics because there is no library known to this enum.
    Custom(Word),
}

impl BurnPolicyConfig {
    /// Returns the procedure root of the active policy this config resolves to.
    pub fn root(self) -> Word {
        match self {
            Self::AllowAll => BurnAllowAll::root(),
            Self::OwnerOnly => BurnOwnerOnly::root(),
            Self::Custom(root) => root,
        }
    }

    /// Returns the [`AccountComponent`] corresponding to the active policy.
    ///
    /// # Panics
    ///
    /// Panics for [`BurnPolicyConfig::Custom`] — custom policies must be installed by the caller
    /// directly.
    pub(crate) fn into_component(self) -> AccountComponent {
        match self {
            Self::AllowAll => BurnAllowAll.into(),
            Self::OwnerOnly => BurnOwnerOnly.into(),
            Self::Custom(_) => panic!(
                "BurnPolicyConfig::Custom does not resolve to a built-in component; install the corresponding component separately",
            ),
        }
    }
}
