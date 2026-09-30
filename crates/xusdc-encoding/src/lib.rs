//! The xUSDC-on-Miden Rust mirror and test harness: the Rust mirror of the hand-written MASM encoding
//! module, the canonical golden-vector loader / generator, and the faucet account composition
//! (the [`account::xreserve::XReserveStablecoinBuilder`], which validates at build time that
//! the attestation mint policy is the active mint policy, so the attestation-gated path is the
//! sole supply-increasing surface).
//!
//! The four encoding routines are bytes32 hashing, the uint256 → AssetAmount reducer, the
//! Rust-primary AccountId codec, and the DepositIntent layout + parser.

pub mod account;
pub mod errors;
pub mod note;
pub mod vectors;
pub mod xreserve;

/// Harness-only surface, behind the `testing` feature: the shipped MASM library as a link target.
#[cfg(feature = "testing")]
pub mod xreserve_lib;

/// The crate-root faucet-account constructor: the single entry that turns deploy parameters into the
/// deployable, attestation-gated xUSDC faucet [`account::xreserve::XReserveStablecoinBuilder`]-composed
/// `Account`. Surfaced at the library root so account construction is traceable from the top.
/// Beside it, the genesis-only mutation that records consumed deposit nonces on a built faucet.
pub use account::xreserve::{build_faucet_account, record_used_nonces};

/// Path of the one canonical golden-vector artifact, loaded by reference from both the Rust
/// unit tests and the MASM execution tests.
pub fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/xreserve-encoding-vectors.json")
}
