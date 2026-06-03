//! Transfer policy components and the transfer policy descriptor used by
//! [`super::TokenPolicyManager`] for both the send and receive policy kinds.
//!
//! Layout convention inside this module:
//! - File at the root (e.g. `allow_all`, `basic_blocklist`, `basic_allowlist`) = a transfer policy
//!   variant. Each exports a `check_policy` procedure that the kernel invokes via `call` through
//!   the protocol-reserved callback slots.
//! - Folder at the root (e.g. `blocklist`, `allowlist`) = a primitive bundle: storage namespace +
//!   helpers + auth-gated admin component(s) that maintain the storage. Primitives are not transfer
//!   policies by themselves; they are consumed by policy variants.

use alloc::vec::Vec;

use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot};
use thiserror::Error;

mod allow_all;
mod allowlist;
mod basic_allowlist;
mod basic_blocklist;
mod blocklist;

pub use allow_all::TransferAllowAll;
pub use allowlist::{AllowlistOwnerControlled, AllowlistStorage};
pub use basic_allowlist::BasicAllowlist;
pub use basic_blocklist::BasicBlocklist;
pub use blocklist::{BlocklistOwnerControlled, BlocklistStorage};

// TRANSFER POLICY ERROR
// ================================================================================================

/// Errors returned by [`TransferPolicy::custom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransferPolicyError {
    /// The procedure root supplied to [`TransferPolicy::custom`] is not exported by any of
    /// the provided components.
    #[error(
        "custom transfer policy root must match a procedure root in one of the provided components"
    )]
    RootNotInComponents,
}

// TRANSFER POLICY
// ================================================================================================

/// Descriptor for the transfer policy registered with a [`super::TokenPolicyManager`] for either
/// the send or the receive kind.
///
/// A transfer policy binds together the procedure root that the kernel dispatches to (via `call`,
/// through the protocol-reserved callback slots) with any companion [`AccountComponent`]s that
/// must be installed on the account for that procedure root to work.
///
/// The same descriptor applies to both send (`on_before_asset_added_to_note`) and receive
/// (`on_before_asset_added_to_account`) callbacks — the policy procedure receives no direction
/// parameter and reads the relevant account context via `native_account::get_id`.
///
/// The companion components carried by the descriptor are inlined into the account by the
/// [`super::TokenPolicyManager`] when it is converted into account components.
#[derive(Debug, Clone)]
pub struct TransferPolicy {
    root: AccountProcedureRoot,
    components: Vec<AccountComponent>,
}

impl TransferPolicy {
    /// Returns a transfer policy that accepts every transfer unconditionally.
    ///
    /// Resolves to [`TransferAllowAll::root`] and ships the companion [`TransferAllowAll`]
    /// component.
    pub fn allow_all() -> Self {
        Self {
            root: TransferAllowAll::root(),
            components: vec![TransferAllowAll.into()],
        }
    }

    /// Returns a transfer policy that rejects transfers whose native account is in the
    /// `blocked_accounts` map, starting with an empty blocklist. To seed initial entries use
    /// [`Self::with_basic_blocklist`].
    pub fn empty_basic_blocklist() -> Self {
        Self {
            root: BasicBlocklist::root(),
            components: vec![BasicBlocklist::default().into()],
        }
    }

    /// Returns a basic-blocklist transfer policy seeded with the given initial blocked accounts.
    pub fn with_basic_blocklist<I>(blocked_accounts: I) -> Self
    where
        I: IntoIterator<Item = AccountId>,
    {
        Self {
            root: BasicBlocklist::root(),
            components: vec![BasicBlocklist::with_blocked_accounts(blocked_accounts).into()],
        }
    }

    /// Returns a transfer policy that rejects transfers whose native account is not in the
    /// `allowed_accounts` map, starting with an empty allowlist (every transfer rejected). To
    /// seed initial entries use [`Self::with_basic_allowlist`].
    pub fn empty_basic_allowlist() -> Self {
        Self {
            root: BasicAllowlist::root(),
            components: vec![BasicAllowlist::default().into()],
        }
    }

    /// Returns a transfer policy that rejects transfers whose native account is not in the
    /// `allowed_accounts` map. The provided [`AllowlistStorage`] seeds the initial allowlist
    /// entries at component-construction time.
    pub fn with_basic_allowlist(allow_list: AllowlistStorage) -> Self {
        Self {
            root: BasicAllowlist::root(),
            components: vec![BasicAllowlist::from(allow_list).into()],
        }
    }

    /// Returns a transfer policy resolving to `root` and shipping the provided companion
    /// `components` (anything that can be converted into an [`AccountComponent`]).
    ///
    /// # Errors
    ///
    /// Returns [`TransferPolicyError::RootNotInComponents`] if `root` is not the procedure
    /// root of any procedure exported by the provided components.
    pub fn custom<I>(root: AccountProcedureRoot, components: I) -> Result<Self, TransferPolicyError>
    where
        I: IntoIterator,
        I::Item: Into<AccountComponent>,
    {
        let components: Vec<AccountComponent> = components.into_iter().map(Into::into).collect();
        if !components.iter().any(|component| component.has_procedure(root)) {
            return Err(TransferPolicyError::RootNotInComponents);
        }
        Ok(Self { root, components })
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl IntoIterator for TransferPolicy {
    type Item = AccountComponent;
    type IntoIter = alloc::vec::IntoIter<AccountComponent>;

    /// Yields the [`AccountComponent`]s carried by this transfer policy descriptor in
    /// installation order.
    fn into_iter(self) -> Self::IntoIter {
        self.components.into_iter()
    }
}
