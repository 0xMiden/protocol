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
//! for set-time validation. Every policy is dispatched via `dyncall`, so it runs in its own memory
//! context behind the standard `call` ABI and cannot reach the dispatching faucet's procedure
//! locals. Mint and burn are dispatched by `exec`-invoked wrappers; send and receive are
//! dispatched by `invoke_send_policy` / `invoke_receive_policy` wrappers whose roots live in
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
//! manager's `dyncall` can dispatch to it.
//!
//! A faucet constructs the manager via [`TokenPolicyManager::builder`], setting the required
//! `active_*_policy` for each kind (and optionally any number of reserved `allowed_*_policy`
//! entries), then passes the built manager directly to
//! [`miden_protocol::account::AccountBuilder::with_components`].

use miden_protocol::account::{AccountStorage, StorageSlotName};
use thiserror::Error;

mod burn;
mod manager;
mod mint;
mod transfer;

pub use burn::{BurnAllowAll, BurnOwnerOnly, BurnPolicy, BurnPolicyError, MinBurnAmount};
pub use manager::{TokenPolicyManager, TokenPolicyManagerBuilder};
pub use mint::{MintAllowAll, MintOwnerOnly, MintPolicy, MintPolicyError};
pub use transfer::{
    AllowlistManager,
    AllowlistStorage,
    BasicAllowlist,
    BasicBlocklist,
    BlocklistManager,
    BlocklistStorage,
    TransferAllowAll,
    TransferPolicy,
    TransferPolicyError,
};

// POLICY DEPENDENCY
// ================================================================================================

/// Error returned by [`verify_policy_dependencies`] when the account does not provide a storage
/// slot that one of its registered policies reads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "policy requires storage slot `{slot_name}`, which no component installed on the account provides"
)]
pub struct MissingPolicyDependency {
    slot_name: StorageSlotName,
}

impl MissingPolicyDependency {
    /// Returns the name of the missing storage slot.
    pub fn slot_name(&self) -> &StorageSlotName {
        &self.slot_name
    }
}

/// Verifies that `storage` provides every slot in `required_slots`, which is typically obtained
/// from [`TokenPolicyManager::required_storage_slots`].
///
/// # Errors
///
/// Returns [`MissingPolicyDependency`] for the first required slot that `storage` does not have.
pub fn verify_policy_dependencies(
    required_slots: &[StorageSlotName],
    storage: &AccountStorage,
) -> Result<(), MissingPolicyDependency> {
    for slot_name in required_slots {
        if storage.get(slot_name).is_none() {
            return Err(MissingPolicyDependency { slot_name: slot_name.clone() });
        }
    }

    Ok(())
}
