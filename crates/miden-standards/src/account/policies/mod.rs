//! Token (mint and burn) policy account components.
//!
//! Policies are the procedures that gate minting and burning of tokens. The policy state is owned
//! by a single [`TokenPolicyManager`] component:
//! - It owns four storage slots (active/allowed maps for mint and burn).
//! - It exposes the `set_*_policy` / `get_*_policy` / `execute_*_policy` procedures via a single
//!   MASM library.
//!
//! Authority for switching policies is provided by the separate
//! [`Authority`][crate::account::access::Authority] component, which must be installed on the
//! account alongside the policy manager.
//!
//! Storage-free policy components (e.g. [`MintAllowAll`], [`BurnOwnerOnly`]) install a specific
//! policy procedure on the account so that the manager's `dynexec` can dispatch to it.
//!
//! A faucet installs the manager together with at least one mint and one burn policy component
//! whose procedure roots are registered in the manager's allowed-policies maps. Pass a
//! [`TokenPolicyManager`] directly to
//! [`miden_protocol::account::AccountBuilder::with_components`] to install the manager and the
//! configured mint/burn policy components in one call.

pub mod burn;
mod manager;
pub mod mint;

pub use burn::{BurnAllowAll, BurnOwnerOnly, BurnPolicyConfig};
pub use manager::TokenPolicyManager;
pub use mint::{MintAllowAll, MintOwnerOnly, MintPolicyConfig};
