//! Token policy account components.
//!
//! Policies are the procedures that gate minting, burning, and transferring of tokens. The policy
//! state is owned by a single [`TokenPolicyManager`] component, which exposes four kinds of
//! policies:
//! - **mint** — gate mint operations
//! - **burn** — gate burn operations
//! - **send** — fired by the protocol's `on_before_asset_added_to_note` callback when the issuing
//!   faucet's asset is added to a note (transfer "from" side)
//! - **receive** — fired by the protocol's `on_before_asset_added_to_account` callback when the
//!   issuing faucet's asset is added to an account vault (transfer "to" side)
//!
//! The manager owns an `active_*_policy` slot per mint / burn kind (and dispatches them via
//! `dynexec`) plus an `allowed_*_policies` map per kind for set-time validation. The active roots
//! for send and receive policies reside directly in the protocol-reserved
//! callback slots so the kernel dispatches to them via `call`.
//!
//! Storage-free policy components (e.g. [`MintAllowAll`], [`BurnOwnerOnly`],
//! [`TransferAllowAll`]) install a specific policy procedure on the account so that the
//! manager's `dynexec` can dispatch to it.
//!
//! A faucet installs the manager via the chained builder
//! [`TokenPolicyManager::with_mint_policy`] / [`TokenPolicyManager::with_burn_policy`] /
//! [`TokenPolicyManager::with_send_policy`] / [`TokenPolicyManager::with_receive_policy`] and
//! passes it directly to [`miden_protocol::account::AccountBuilder::with_components`].

use miden_protocol::Word;

pub mod burn;
mod manager;
pub mod mint;
pub mod transfer;

pub use burn::{BurnAllowAll, BurnOwnerOnly, BurnPolicyConfig};
pub use manager::{PolicyConfig, TokenPolicyManager};
pub use mint::{MintAllowAll, MintOwnerOnly, MintPolicyConfig};
pub use transfer::{
    BasicBlocklist,
    Blocklist,
    OwnerManagedBlocklist,
    TransferAllowAll,
    TransferPolicy,
};

// POLICY AUTHORITY
// ================================================================================================

/// Identifies which authority is allowed to manage policies for a faucet.
///
/// Shared across all policy kinds — the manager stores a single value that gates
/// `set_mint_policy`, `set_burn_policy`, `set_send_policy`, and `set_receive_policy`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyAuthority {
    /// Policy changes are authorized by the account's authentication component logic.
    AuthControlled = 0,
    /// Policy changes are authorized by the external account owner.
    OwnerControlled = 1,
}

impl From<PolicyAuthority> for Word {
    fn from(value: PolicyAuthority) -> Self {
        Word::from([value as u8, 0, 0, 0])
    }
}

// POLICY REGISTRATION
// ================================================================================================

/// Indicates whether a policy entry is the currently active one (written into the
/// `active_*_policy` slot) or a reserved alternative (kept in the `allowed_*_policies` map for
/// future activation via `set_*_policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRegistration {
    /// Becomes the policy stored in the `active_*_policy` slot for its kind (mint, burn, send,
    /// or receive). Exactly one `Active` entry is allowed per kind.
    Active,
    /// Registered in the `allowed_*_policies` map for its kind. Can be promoted to active
    /// later by calling the matching `set_*_policy` procedure.
    Reserved,
}
