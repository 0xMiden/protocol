//! Mint and burn policy account components and their policy manager.
//!
//! Policies are the procedures that gate minting and burning of tokens. They are installed on a
//! faucet alongside a [`manager::MintPolicyManager`] / [`manager::BurnPolicyManager`] which owns
//! the three manager storage slots (authority, active_policy, allowed_policies) and exposes the
//! `set_*_policy` / `get_*_policy` / `execute_*_policy` procedures.
//!
//! Policies are grouped by family (matching the `asm/account_components/{mint,burn}_policies/`
//! layout):
//! - Top-level policies (e.g. [`mint::AllowAll`], [`burn::AllowAll`]) — universal, no family.
//! - [`mint::owner_controlled`] / [`burn::owner_controlled`] — policies intended for use with an
//!   owner-controlled manager.

pub mod burn;
pub mod manager;
pub mod mint;
