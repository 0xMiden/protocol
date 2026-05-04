//! Token (mint, burn, and transfer) policy account components.
//!
//! Policies are the procedures that gate minting, burning, and transferring of tokens. The policy
//! state is owned by a single [`TokenPolicyManager`] component:
//! - It owns seven storage slots (shared authority + active/allowed maps for mint, burn, and
//!   transfer) plus the asset-callback slots that wire its `on_before_asset_added_to_*` procedures
//!   into the protocol's callback dispatch.
//! - It exposes the `set_*_policy` / `get_*_policy` / `execute_*_policy` procedures via a single
//!   MASM library.
//!
//! Storage-free policy components (e.g. [`MintAllowAll`], [`BurnOwnerOnly`],
//! [`TransferAllowAll`]) install a specific policy procedure on the account so that the
//! manager's `dynexec` can dispatch to it.
//!
//! A faucet installs the manager together with at least one mint, one burn, and one transfer
//! policy component whose procedure roots are registered in the manager's allowed-policies maps.
//! Pass a [`TokenPolicyManager`] directly to
//! [`miden_protocol::account::AccountBuilder::with_components`] to install the manager and the
//! configured policy components in one call.

use miden_protocol::Word;

pub mod burn;
mod manager;
pub mod mint;
pub mod transfer;

pub use burn::{BurnAllowAll, BurnOwnerOnly, BurnPolicyConfig};
pub use manager::TokenPolicyManager;
pub use mint::{MintAllowAll, MintOwnerOnly, MintPolicyConfig};
pub use transfer::{TransferAllowAll, TransferIfNotBlocklisted, TransferPolicyConfig};

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
