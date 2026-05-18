//! Transfer policy components and the transfer policy enum used by
//! [`super::TokenPolicyManager`] for both the send and receive policy kinds.
//!
//! Layout convention inside this module:
//! - File at the root (e.g. `allow_all`, `basic_blocklist`) = a transfer policy variant. Each
//!   exports a `check_policy` procedure that the kernel invokes via `call` through the
//!   protocol-reserved callback slots.
//! - Folder at the root (e.g. `blocklist`) = a primitive bundle: storage namespace + helpers
//!   + auth-gated admin component(s) that maintain the storage. Primitives are not transfer
//!     policies by themselves; they are consumed by policy variants.

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

mod allow_all;
mod basic_blocklist;
mod basic_pausable;
mod blocklist;
mod pausable_blocklist;

pub use allow_all::TransferAllowAll;
pub use basic_blocklist::BasicBlocklist;
pub use basic_pausable::BasicPausable;
pub use blocklist::{BlocklistOwnerControlled, BlocklistStorage};
pub use pausable_blocklist::PausableBlocklist;

// TRANSFER POLICY
// ================================================================================================

/// Selects a transfer policy variant for the send or receive kind on a
/// [`super::TokenPolicyManager`].
///
/// The same variants apply to both send (`on_before_asset_added_to_note`) and receive
/// (`on_before_asset_added_to_account`) callbacks — the policy procedure receives no direction
/// parameter and reads the relevant account context via `native_account::get_id`.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum TransferPolicy {
    /// Active policy = [`TransferAllowAll::root`] (the callback predicate accepts unconditionally).
    #[default]
    AllowAll,
    /// Active policy = [`BasicBlocklist::root`]. Resolves into a [`BasicBlocklist`] component
    /// with an empty initial blocklist; to seed initial entries, install [`BasicBlocklist`]
    /// explicitly via [`BasicBlocklist::with_blocked_accounts`] and select the policy via
    /// [`TransferPolicy::Custom`] with [`BasicBlocklist::root`].
    Blocklist,
    /// Active policy = [`BasicPausable::root`]. Resolves into a [`BasicPausable`] component that
    /// starts unpaused; to seed an initial paused state, install [`BasicPausable`] explicitly
    /// via [`BasicPausable::paused`] and select the policy via [`TransferPolicy::Custom`] with
    /// [`BasicPausable::root`].
    Pausable,
    /// Active policy = [`PausableBlocklist::root`]. Resolves into a [`PausableBlocklist`]
    /// component that starts unpaused and with no initially blocked accounts; to seed either
    /// state, install [`PausableBlocklist`] explicitly via
    /// [`PausableBlocklist::with_initial_pause_state`] /
    /// [`PausableBlocklist::with_initial_blocked_accounts`] and select the policy via
    /// [`TransferPolicy::Custom`] with [`PausableBlocklist::root`].
    PausableBlocklist,
    /// Active policy = the provided root. The corresponding component(s) must be installed by
    /// the caller separately; resolving this variant into built-in components yields an empty
    /// list.
    Custom(AccountProcedureRoot),
}

impl TransferPolicy {
    /// Returns the procedure root of the policy this variant resolves to.
    pub fn root(self) -> AccountProcedureRoot {
        match self {
            Self::AllowAll => TransferAllowAll::root(),
            Self::Blocklist => BasicBlocklist::root(),
            Self::Pausable => BasicPausable::root(),
            Self::PausableBlocklist => PausableBlocklist::root(),
            Self::Custom(root) => root,
        }
    }

    /// Returns the [`AccountComponent`]s that must accompany this transfer policy variant.
    ///
    /// For [`Self::Blocklist`] this is a [`BasicBlocklist`] component with no initial blocked
    /// accounts; for [`Self::Pausable`] this is a [`BasicPausable`] component that starts
    /// unpaused; for [`Self::PausableBlocklist`] this is a [`PausableBlocklist`] component
    /// that starts unpaused and with no initially blocked accounts. For [`Self::Custom`]
    /// this is empty — the caller installs whatever the chosen root requires.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        match self {
            Self::AllowAll => vec![TransferAllowAll.into()],
            Self::Blocklist => vec![BasicBlocklist::default().into()],
            Self::Pausable => vec![BasicPausable::default().into()],
            Self::PausableBlocklist => vec![PausableBlocklist::default().into()],
            Self::Custom(_) => Vec::new(),
        }
    }
}
