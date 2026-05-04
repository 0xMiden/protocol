//! Token (mint and burn) policy account components.
//!
//! Policies are the procedures that gate minting and burning of tokens. The policy state is owned
//! by a single [`TokenPolicyManager`] component:
//! - It owns five storage slots (shared authority + active/allowed maps for mint and burn).
//! - It exposes the `set_*_policy` / `get_*_policy` / `execute_*_policy` procedures via a single
//!   MASM library.
//!
//! Storage-free policy components (e.g. [`MintAllowAll`], [`BurnOwnerOnly`]) install a specific
//! policy procedure on the account so that the manager's `dynexec` can dispatch to it.
//!
//! A faucet installs the manager together with at least one mint and one burn policy component
//! whose procedure roots are registered in the manager's allowed-policies maps. Pass a
//! [`TokenPolicyManager`] directly to
//! [`miden_protocol::account::AccountBuilder::with_components`] to install the manager and the
//! configured mint/burn policy components in one call.

use miden_protocol::Word;

pub mod burn;
mod manager;
pub mod mint;

pub use burn::{BurnAllowAll, BurnOwnerOnly, BurnPolicyConfig};
pub use manager::TokenPolicyManager;
pub use mint::{MintAllowAll, MintOwnerOnly, MintPolicyConfig};

// POLICY AUTHORITY
// ================================================================================================

/// Identifies which authority is allowed to manage policies for a faucet.
///
/// Shared between mint and burn — the manager stores a single value that gates both
/// `set_mint_policy` and `set_burn_policy`.
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
