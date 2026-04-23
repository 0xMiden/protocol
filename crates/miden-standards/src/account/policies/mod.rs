//! Mint and burn policy account components and their policy managers.
//!
//! Policies are the procedures that gate minting and burning of tokens. Each side ([`mint`],
//! [`burn`]) exposes:
//! - A [`PolicyManager`](mint::PolicyManager) that owns the three manager storage slots and the
//!   `set_*_policy` / `get_*_policy` / `execute_*_policy` procedures.
//! - Storage-free policy components (e.g. `mint::AllowAll`, `mint::owner_controlled::OwnerOnly`)
//!   that install a specific policy procedure on the account.
//!
//! A faucet installs the manager together with at least one policy component whose procedure root
//! is registered in the manager's allowed-policies map.

pub mod burn;
pub mod mint;
