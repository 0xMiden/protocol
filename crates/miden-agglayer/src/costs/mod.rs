//! Benchmarked consumption costs of the agglayer notes.
//!
//! Each constant is the number of VM cycles of the canonical network-account transaction
//! consuming the note - measured by the `bench-transaction` binary. See
//! [`miden_standards::note::costs`] for the full definition of the canonical transaction, the
//! cycle denomination, why the values are estimates rather than guaranteed worst cases, and the
//! [`NetworkNotePricer`](miden_standards::note::costs::NetworkNotePricer) turning cycle costs
//! into fees; build it with [`AgglayerNote::note_cost`](crate::AgglayerNote::note_cost) as the
//! lookup to price agglayer and standard notes through a single pricer.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

mod table;
pub use table::*;
