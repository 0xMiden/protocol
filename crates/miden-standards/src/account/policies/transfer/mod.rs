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

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;

mod allow_all;
mod basic_blocklist;
mod blocklist;

pub use allow_all::TransferAllowAll;
pub use basic_blocklist::BasicBlocklist;
pub use blocklist::{BlocklistStorage, OwnerControlledBlocklist};

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
    /// Active policy = the provided root. The corresponding component(s) must be installed by
    /// the caller separately; resolving this variant into built-in components yields an empty
    /// list.
    Custom(Word),
}

impl TransferPolicy {
    /// Returns the procedure root of the policy this variant resolves to.
    pub fn root(self) -> Word {
        match self {
            Self::AllowAll => TransferAllowAll::root(),
            Self::Blocklist => BasicBlocklist::root(),
            Self::Custom(root) => root,
        }
    }

    /// Returns the [`AccountComponent`]s that must accompany this transfer policy variant.
    ///
    /// For [`Self::Blocklist`] this is a [`BasicBlocklist`] component with no initial blocked
    /// accounts. For [`Self::Custom`] this is empty — the caller installs whatever the chosen
    /// root requires.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        match self {
            Self::AllowAll => vec![TransferAllowAll.into()],
            Self::Blocklist => vec![BasicBlocklist::default().into()],
            Self::Custom(_) => Vec::new(),
        }
    }
}
