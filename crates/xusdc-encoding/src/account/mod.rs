//! Faucet account composition for the xUSDC faucet — hosts the faucet account builder that
//! composes the full attestation-gated faucet account.

pub mod xreserve;

/// The crate-root faucet-account constructor and the convertible `xreserve` component type, surfaced
/// at the account-module root so account construction is discoverable one level up from the builder.
pub use xreserve::{build_faucet_account, record_used_nonces, XReserveFaucetExtension};
