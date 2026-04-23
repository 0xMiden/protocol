//! Mint policy account components.
//!
//! Mint policies are the procedures that gate the minting of tokens. This module exposes the
//! policy procedures as standalone, storage-free [`AccountComponent`]s. They are installed on a
//! faucet alongside a [`crate::account::policy_manager::MintPolicyManager`] which owns the manager
//! procedures and the 3 policy-manager storage slots.
//!
//! Policies are grouped by family (matching the `asm/account_components/mint_policies/` layout):
//! - [`MintAuthControlled`] — policies intended for use with an auth-controlled manager (today:
//!   `allow_all`).
//! - [`MintOwnerControlled`] — policies intended for use with an owner-controlled manager (today:
//!   `owner_only`).
//!
//! Each family also exposes a `*Config` enum describing the initial active policy for convenience
//! when constructing a manager.
//!
//! [`AccountComponent`]: miden_protocol::account::AccountComponent

mod auth_controlled;
mod owner_controlled;

pub use self::auth_controlled::{MintAuthControlled, MintAuthControlledConfig};
pub use self::owner_controlled::{MintOwnerControlled, MintOwnerControlledConfig};
