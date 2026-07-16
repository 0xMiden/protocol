//! Fee account components.
//!
//! [`FeeManager`] is structured like the token policy managers
//! (see [`crate::account::policies`]): it owns an `active_fee_policy_proc_root` slot plus an
//! `allowed_fee_policy_proc_roots` map slot for set-time validation, and its `estimate_note_fee`
//! procedure dispatches to the active fee policy via `dyncall`. The actual fee computation logic
//! lives in fee policy components ([`ConstantFeePolicy`]), and the active
//! policy can be switched to any allowlisted policy root through the authority-gated
//! `set_fee_policy` procedure (authorized via the account-wide
//! [`Authority`][crate::account::access::Authority] component, which must be installed alongside
//! the manager).
//!
//! An account constructs the manager via [`FeeManager::builder`], setting the required
//! `active_fee_policy` (and optionally any number of reserved `allowed_fee_policy` entries),
//! then passes the built manager directly to
//! [`miden_protocol::account::AccountBuilder::with_components`].

mod fee_manager;
mod policies;

pub use fee_manager::{FeeManager, FeeManagerBuilder};
pub use policies::{ConstantFeePolicy, FeePolicy, FeePolicyError};
