//! Burn policy account components.
//!
//! Burn policies are the procedures that gate the burning of tokens. This module exposes the
//! policy procedures as standalone, storage-free [`AccountComponent`]s. They are installed on a
//! faucet alongside a [`crate::account::policy_manager::BurnPolicyManager`] which owns the manager
//! procedures and the 3 policy-manager storage slots.
//!
//! Policies are grouped by family (matching the `asm/account_components/burn_policies/` layout):
//! - [`BurnAuthControlled`] — policies intended for use with an auth-controlled manager (today:
//!   `allow_all`).
//! - [`BurnOwnerControlled`] — policies intended for use with an owner-controlled manager (today:
//!   `owner_only`).
//!
//! Each family also exposes a `*Config` enum describing the initial active policy for convenience
//! when constructing a manager.
//!
//! [`AccountComponent`]: miden_protocol::account::AccountComponent

mod auth_controlled;
mod owner_controlled;

pub use self::auth_controlled::{BurnAuthControlled, BurnAuthControlledConfig};
pub use self::owner_controlled::{BurnOwnerControlled, BurnOwnerControlledConfig};
