//! Transfer policy components and the transfer policy enum used by
//! [`super::TokenPolicyManager`] for both the send and receive policy kinds.
//!
//! Layout convention inside this module:
//! - File at the root (e.g. `allow_all`, `basic_blocklist`) = a transfer policy variant. Each
//!   exports a `check_policy` procedure that the kernel invokes via `call` through the
//!   protocol-reserved callback slots.
//! - Folder at the root (e.g. [`blocklist`]) = a primitive bundle: storage namespace + helpers
//!   + auth-gated admin component(s) that maintain the storage. Primitives are not transfer
//!   policies by themselves; they are consumed by policy variants.

use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountComponent;

mod allow_all;
mod basic_blocklist;
pub mod blocklist;

pub use allow_all::TransferAllowAll;
pub use basic_blocklist::BasicBlocklist;
pub use blocklist::{Blocklist, OwnerManagedBlocklist};

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
    /// Active policy = [`BasicBlocklist::root`]. The policy component installs the
    /// `blocked_accounts` storage map alongside its predicate procedure.
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

    /// Whether the manager should register the protocol's `on_before_asset_added_to_*` callbacks
    /// when this variant is installed for either the send or the receive kind.
    ///
    /// For [`Self::AllowAll`] there is no enforcement to perform, so callbacks are skipped.
    /// Beyond the dispatch overhead this also affects the asset value word — a faucet with
    /// callback slots populated mints assets that carry `AssetCallbackFlag::Enabled`, which
    /// would change the asset commitment for any consumer that constructs the expected asset
    /// without a flag.
    ///
    /// `Custom` is treated as enforcement-bearing — if you opt into a custom policy, you opt
    /// into callback dispatch.
    pub(crate) fn requires_callbacks(self) -> bool {
        match self {
            Self::AllowAll => false,
            Self::Blocklist | Self::Custom(_) => true,
        }
    }

    /// Returns the [`AccountComponent`]s that must accompany this transfer policy variant.
    ///
    /// For [`Self::Blocklist`] this is the policy component, which installs both the predicate
    /// procedure and the `blocked_accounts` storage map. For [`Self::Custom`] this is empty —
    /// the caller installs whatever the chosen root requires.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        match self {
            Self::AllowAll => vec![TransferAllowAll.into()],
            Self::Blocklist => vec![BasicBlocklist.into()],
            Self::Custom(_) => Vec::new(),
        }
    }
}
