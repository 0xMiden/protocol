//! Mint and burn policy account components.
//!
//! Policies are the procedures that gate minting and burning of tokens. Each side ([`mint`],
//! [`burn`]) exposes:
//! - A policy manager component ([`MintPolicyManager`] / [`BurnPolicyManager`]) that owns the three
//!   manager storage slots and the `set_*_policy` / `get_*_policy` / `execute_*_policy` procedures.
//! - Storage-free policy components (e.g. [`MintAllowAll`], [`MintOwnerOnly`]) that install a
//!   specific policy procedure on the account.
//!
//! A faucet installs the manager together with at least one policy component whose procedure
//! root is registered in the manager's allowed-policies map.
//!
//! Internally both managers share a single generic implementation living in a crate-private
//! `manager` module.
//!
//! [`mint`]: self::mint
//! [`burn`]: self::burn

use miden_protocol::Word;

pub mod burn;
mod manager;
pub mod mint;

pub use burn::{BurnAllowAll, BurnOwnerControlledConfig, BurnOwnerOnly, BurnPolicyManager};
pub use mint::{MintAllowAll, MintOwnerControlledConfig, MintOwnerOnly, MintPolicyManager};

// POLICY AUTHORITY
// ================================================================================================

/// Identifies which authority is allowed to manage the active policy for a faucet.
///
/// Shared between mint and burn policy managers — the authority slot stores the same encoding
/// (`0` = `AuthControlled`, `1` = `OwnerControlled`) regardless of side.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
