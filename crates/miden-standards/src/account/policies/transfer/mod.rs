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
/// Construct via [`Self::allow_all`], [`Self::basic_blocklist`],
/// [`Self::basic_blocklist_with_initial`], [`Self::basic_allowlist`], [`Self::custom`], or
/// [`Self::from_components`]. The companion components carried by the descriptor are inlined into
/// the account by the [`super::TokenPolicyManager`] when it is converted into account components.
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
    /// [`Self::basic_blocklist_with_initial`].
    pub fn basic_blocklist() -> Self {
        Self {
            root: BasicBlocklist::root(),
            components: vec![BasicBlocklist::default().into()],
        }
    }

    /// Returns a basic-blocklist transfer policy seeded with the given initial blocked accounts.
    pub fn basic_blocklist_with_initial<I>(blocked_accounts: I) -> Self
    where
        I: IntoIterator<Item = AccountId>,
    {
        Self {
            root: BasicBlocklist::root(),
            components: vec![BasicBlocklist::with_blocked_accounts(blocked_accounts).into()],
        }
    }

    /// Returns a transfer policy that rejects transfers whose native account is not in the
    /// `allowed_accounts` map. The provided [`AllowlistStorage`] seeds the initial allowlist
    /// entries at component-construction time.
    pub fn basic_allowlist(allow_list: AllowlistStorage) -> Self {
        Self {
            root: BasicAllowlist::root(),
            components: vec![BasicAllowlist::from(allow_list).into()],
        }
    }

    /// Returns a transfer policy resolving to the provided procedure root. The corresponding
    /// component(s) must be installed by the caller separately — this descriptor carries no
    /// companion components.
    pub fn custom(root: AccountProcedureRoot) -> Self {
        Self { root, components: Vec::new() }
    }

    /// Returns a transfer policy resolving to the provided procedure root and shipping the
    /// provided companion components. Use this for fully bespoke policy compositions where the
    /// caller wants the manager to install the companion components alongside the procedure
    /// root.
    pub fn from_components(root: AccountProcedureRoot, components: Vec<AccountComponent>) -> Self {
        Self { root, components }
    }

    /// Returns the procedure root of the policy this descriptor resolves to.
    pub fn root(&self) -> AccountProcedureRoot {
        self.root
    }

    /// Returns the [`AccountComponent`]s that must accompany this transfer policy.
    pub(crate) fn into_components(self) -> Vec<AccountComponent> {
        self.components
    }
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}
