//! Burn policy components and the burn policy configuration enum used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;
use miden_protocol::asset::AssetAmount;

mod allow_all;
mod min_burn_amount;
mod owner_only;

pub use allow_all::BurnAllowAll;
pub use min_burn_amount::MinBurnAmount;
pub use owner_only::BurnOwnerOnly;

// CONFIG
// ================================================================================================

/// Selects which burn policy is registered with a [`super::TokenPolicyManager`].
///
/// Pass to [`super::TokenPolicyManager::with_burn_policy`] together with a
/// [`super::PolicyRegistration`] to register the policy as either active or as a reserved
/// alternative.
#[derive(Debug, Clone, Copy, Default)]
pub enum BurnPolicyConfig {
    /// Policy root = [`BurnAllowAll::root`] (burns open to anyone).
    #[default]
    AllowAll,
    /// Policy root = [`BurnOwnerOnly::root`] (burns gated by the account owner).
    OwnerOnly,
    /// Policy root = [`MinBurnAmount::root`] (burns below the configured minimum are rejected).
    ///
    /// The wrapped value is the initial minimum burn amount written to the policy's storage
    /// slot. It can be updated at runtime through the owner-gated `set_min_burn_amount`
    /// procedure.
    MinBurnAmount(AssetAmount),
    /// Policy root = the provided word. The corresponding component must be installed by the
    /// caller separately; resolving this variant into built-in components yields an empty list.
    Custom(Word),
}

impl BurnPolicyConfig {
    /// Returns the procedure root of the policy this variant resolves to.
    pub fn root(self) -> Word {
        match self {
            Self::AllowAll => BurnAllowAll::root().as_word(),
            Self::OwnerOnly => BurnOwnerOnly::root().as_word(),
            Self::MinBurnAmount(_) => MinBurnAmount::root().as_word(),
            Self::Custom(root) => root,
        }
    }

    /// Returns the [`AccountComponent`]s that must accompany this burn policy variant.
    ///
    /// For [`Self::Custom`] this is empty — the caller installs whatever the chosen root
    /// requires.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        match self {
            Self::AllowAll => vec![BurnAllowAll.into()],
            Self::OwnerOnly => vec![BurnOwnerOnly.into()],
            Self::MinBurnAmount(min_burn_amount) => {
                vec![MinBurnAmount::new(min_burn_amount).into()]
            },
            Self::Custom(_) => Vec::new(),
        }
    }
}
