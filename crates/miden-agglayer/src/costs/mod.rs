//! Benchmarked consumption costs of the agglayer notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note - the bridge account (a network account) consumes it on a chain charging
//! a verification base fee - measured by the `bench-transaction` binary and taken as the
//! maximum across the note's benchmarked execution paths. See
//! [`miden_standards::note::costs`] for the full definition of the canonical transaction and
//! the cycle denomination.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when the checked-in values no longer match the measured ones.

mod table;
pub use table::*;
