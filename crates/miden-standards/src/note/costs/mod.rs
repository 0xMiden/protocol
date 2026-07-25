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
//! The values are estimates from canonical scenarios, not worst cases: asset-scaling paths
//! carry 16 callback-free assets (the P2ID/P2IDE cap planned in
//! <https://github.com/0xMiden/protocol/issues/3381>) and action notes run one selector, so
//! callback-carrying or maximally packed notes can exceed the values - do not treat them as
//! guaranteed fee upper bounds.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

mod table;
pub use table::*;
