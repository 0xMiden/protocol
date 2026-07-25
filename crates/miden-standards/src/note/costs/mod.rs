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
//! The values are estimates measured on canonical scenarios, not guaranteed worst cases:
//! asset-count-scaling paths are benchmarked at 16 assets - the planned protocol maximum
//! (see the review of <https://github.com/0xMiden/protocol/pull/3354>), below the current
//! [`miden_protocol::MAX_ASSETS_PER_NOTE`] of 64 - with callback-free assets, and other
//! inputs and action selectors can shift individual costs further. A maximally packed or
//! callback-heavy note can therefore exceed these values: do not treat them as guaranteed
//! fee upper bounds.
//!
//! The table is regenerated with `make update-note-costs`; a snapshot test in
//! `bench-transaction` fails CI when a checked-in value drifts more than 5% from the measured
//! one (small drift from unrelated changes is tolerated - the pricing safety margin dwarfs
//! it).

mod table;
pub use table::*;
