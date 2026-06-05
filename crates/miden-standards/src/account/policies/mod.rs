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
//! The manager owns an `active_*_policy` slot per kind plus an `allowed_*_policies` map per kind
//! for set-time validation. Mint and burn are dispatched via `dynexec` by `exec`-invoked
//! wrappers; send and receive are dispatched by `invoke_send_policy` / `invoke_receive_policy`
//! wrappers whose roots live in
//! the protocol-reserved callback slots, so the kernel `dyncall`s the wrapper, which applies the
//! pause check and then dispatches to the active policy.
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
//! A faucet constructs the manager via [`TokenPolicyManager::builder`], setting the required
//! `active_*_policy` for each kind (and optionally any number of reserved `allowed_*_policy`
//! entries), then passes the built manager directly to
//! [`miden_protocol::account::AccountBuilder::with_components`].

mod burn;
mod manager;
mod mint;
mod transfer;

pub use burn::{BurnAllowAll, BurnOwnerOnly, BurnPolicy, BurnPolicyError, MinBurnAmount};
pub use manager::{TokenPolicyManager, TokenPolicyManagerBuilder};
pub use mint::{MintAllowAll, MintOwnerOnly, MintPolicy, MintPolicyError};
pub use transfer::{
    AllowlistOwnerControlled,
    AllowlistStorage,
    BasicAllowlist,
    BasicBlocklist,
    BlocklistOwnerControlled,
    BlocklistStorage,
    TransferAllowAll,
    TransferPolicy,
    TransferPolicyError,
};
