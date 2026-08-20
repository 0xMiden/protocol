//! The user-facing price oracle interface: a single procedure returning the rate between two
//! assets.
//!
//! The rate is returned as a [`ConversionRate`], rather than a converted amount. Callers apply it
//! with `fee::convert_amount`, which computes `ceil(amount * num / den)` at 128-bit intermediate
//! precision, so both paths round the same way.
//!
//! [`PriceOracle`]'s body does nothing but read a rate provider root from storage and dispatch to
//! it, so the provider can be replaced without changing the MAST root consumers reach it by. This
//! module ships the interface and that dispatch; rate providers and consumer-side conversion
//! helpers are separate components.

mod price_oracle;
mod types;

pub use price_oracle::PriceOracle;
pub use types::ConversionRate;
