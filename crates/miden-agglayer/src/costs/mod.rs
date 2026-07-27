//! Benchmarked consumption costs of the agglayer notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note - measured by the `bench-transaction` binary. See
//! [`miden_standards::note::costs`] for the full definition of the canonical transaction, the
//! cycle denomination, and why the values are estimates rather than guaranteed worst cases.
//! The `NetworkNotePricer` in `miden-tx` turns cycle costs into fees, resolving the agglayer
//! notes through [`AgglayerNote::note_cost`](crate::AgglayerNote::note_cost).
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

mod table;
pub use table::*;
