//! Benchmarked consumption costs of the standard notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note, measured by the `bench-transaction` binary and taken as the maximum
//! across the note's benchmarked execution paths. The canonical transaction consumes the note
//! into an account authenticated with
//! [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) (carrying the functional
//! components the note requires) on a chain charging a verification base fee, so the measured
//! cycles include allowlist checks and TX_FEE note creation.
//!
//! The values are denominated in cycles rather than fee units: the fee charged for a
//! transaction is `verification_base_fee * (ilog2(cycles) + 1)`, and `verification_base_fee`
//! is a block-header parameter that can change independently of these measurements.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when the checked-in values no longer match the measured ones.

mod table;
pub use table::*;
