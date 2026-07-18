//! Benchmarked consumption costs of the standard notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note, measured by the `bench-transaction` binary: an account authenticated
//! with [`AuthNetworkAccount`](crate::account::auth::AuthNetworkAccount) (carrying the
//! components the note requires) consumes the note on a fee-charging chain, so the measured
//! cycles include the allowlist checks and TX_FEE note creation.
//!
//! The values are denominated in cycles rather than fee units, since the fee
//! (`verification_base_fee * (ilog2(cycles) + 1)`) depends on a block-header parameter.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when the checked-in values no longer match the measured ones.

mod table;
pub use table::*;
