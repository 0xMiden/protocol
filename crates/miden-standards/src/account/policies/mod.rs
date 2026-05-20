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
//! Authority for switching policies is provided by the separate
//! [`Authority`][crate::account::access::Authority] component, which must be installed on the
//! account alongside the policy manager. The masm helper `authority::assert_authorized` is
//! `exec`'d from `set_*_policy` to gate runtime policy changes.
//!
//! Storage-free policy components (e.g. [`MintAllowAll`], [`BurnOwnerOnly`],
//! [`TransferAllowAll`]) install a specific policy procedure on the account so that the
//! manager's `dynexec` can dispatch to it.
//!
//! A faucet installs the manager via the chained builder
//! [`TokenPolicyManager::with_mint_policy`] / [`TokenPolicyManager::with_burn_policy`] /
//! [`TokenPolicyManager::with_send_policy`] / [`TokenPolicyManager::with_receive_policy`] and
//! passes it directly to [`miden_protocol::account::AccountBuilder::with_components`].

mod burn;
mod manager;
mod mint;
mod transfer;

pub use burn::{BurnAllowAll, BurnOwnerOnly, BurnPolicyConfig};
pub use manager::{TokenPolicyManager, TokenPolicyManagerError};
pub use mint::{MintAllowAll, MintOwnerOnly, MintPolicyConfig};
pub use transfer::{
    AllowlistOwnerControlled,
    AllowlistStorage,
    BasicAllowlist,
    BasicBlocklist,
    BlocklistOwnerControlled,
    BlocklistStorage,
    TransferAllowAll,
    TransferPolicy,
};

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
