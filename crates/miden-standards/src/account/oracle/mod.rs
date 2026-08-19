//! The price oracle interface: asking what one asset is worth in another.
//!
//! [`PriceOracle`]'s `get_conversion_rate` answers with a numerator and a denominator, the same
//! [`ConversionRate`] shape the fee standard applies through `fee::convert_amount`, so consumers
//! reuse that arithmetic instead of restating it. It also reports how fresh the rate is, since a
//! rate derived from several prices is only as fresh as its stalest input and how stale is too
//! stale is a consumer decision.
//!
//! The procedure body only dispatches to a stored implementation root, which keeps its MAST root -
//! the address consumers resolve over FPI - stable while the pricing behind it changes. This module
//! ships the interface and that dispatch mechanism; pricing implementations and consumer-side
//! conversion helpers are separate components.
//!
//! An asset pair the oracle cannot price yields `den = 0` rather than a failure, so a consumer
//! valuing many assets can decide what an unpriceable one means to it. Ignoring the case still
//! fails closed, because `fee::convert_amount` rejects a zero denominator.

mod price_oracle;
mod types;

pub use price_oracle::PriceOracle;
pub use types::ConversionRate;
