//! The user-facing price oracle interface: a single procedure returning the rate between two
//! assets.
//!
//! The rate is returned as a [`ConversionRate`][crate::utils::ConversionRate]. Callers apply it
//! with `fee::convert_amount` on chain, or with
//! [`ConversionRate::convert`][crate::utils::ConversionRate::convert] off chain; the two round the
//! same way. Alongside it comes the block timestamp of its last update, so a caller can enforce a
//! freshness bound tighter than the rate provider's own.
//!
//! `get_conversion_rate` is a stable MAST root that invokes the rate provider dynamically, so the
//! provider can be replaced without changing the root consumers reach it by. This module ships the
//! interface and that dispatch; rate providers and consumer-side conversion helpers are separate
//! components.

mod price_oracle;

pub use price_oracle::PriceOracle;
