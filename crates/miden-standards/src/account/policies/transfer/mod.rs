//! Transfer policy components and the transfer policy configuration enum used by
//! [`super::TokenPolicyManager`].

use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;

use crate::account::blocklistable::Blocklistable;

mod allow_all;
mod if_not_blocklisted;

pub use allow_all::TransferAllowAll;
pub use if_not_blocklisted::TransferIfNotBlocklisted;

// CONFIG
// ================================================================================================

/// Selects which transfer policy is active when the [`super::TokenPolicyManager`] is first
/// installed.
///
/// Only the chosen policy is registered as allowed by default; runtime switching to another policy
/// requires explicit opt-in via [`super::TokenPolicyManager::with_allowed_transfer_policy`] plus
/// installing the matching policy component.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum TransferPolicyConfig {
    /// Active policy = [`TransferAllowAll::root`] (transfers open to anyone).
    #[default]
    AllowAll,
    /// Active policy = [`TransferIfNotBlocklisted::root`]. Pulls in [`Blocklistable`] so the
    /// faucet has the per-account blocklist storage and admin procedures the predicate reads.
    IfNotBlocklisted,
    /// Active policy = the provided root. The corresponding component(s) must be installed by the
    /// caller separately; resolving this variant into built-in components yields an empty list.
    Custom(Word),
}

impl TransferPolicyConfig {
    /// Returns the procedure root of the active policy this config resolves to.
    pub fn root(self) -> Word {
        match self {
            Self::AllowAll => TransferAllowAll::root(),
            Self::IfNotBlocklisted => TransferIfNotBlocklisted::root(),
            Self::Custom(root) => root,
        }
    }

    /// Whether the manager should register the protocol's `on_before_asset_added_to_*` callbacks
    /// when this config is the initial active transfer policy.
    ///
    /// For [`Self::AllowAll`] there is no enforcement to perform, so callbacks are skipped. This
    /// keeps the issuing faucet free of foreign-context dispatch when it mints its own assets
    /// (the protocol forbids creating a foreign context against the native account).
    ///
    /// `Custom` is treated as enforcement-bearing — if you opt into a custom policy, you opt
    /// into callback dispatch.
    pub(crate) fn requires_callbacks(self) -> bool {
        match self {
            Self::AllowAll => false,
            Self::IfNotBlocklisted | Self::Custom(_) => true,
        }
    }

    /// Returns the [`AccountComponent`]s that must accompany the active transfer policy.
    ///
    /// For [`Self::IfNotBlocklisted`] this includes both the policy component itself and the
    /// [`Blocklistable`] storage/admin component; for [`Self::Custom`] this is empty — the
    /// caller installs whatever the chosen root requires.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        match self {
            Self::AllowAll => vec![TransferAllowAll.into()],
            Self::IfNotBlocklisted => {
                vec![TransferIfNotBlocklisted.into(), Blocklistable::new().into()]
            },
            Self::Custom(_) => Vec::new(),
        }
    }
}
