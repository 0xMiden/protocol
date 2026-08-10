//! Price oracle standards: asking what one asset is worth in another.
//!
//! [`PriceOracle`] is the interface. Its `get_conversion_rate` answers with a numerator and a
//! denominator, the same `ConversionRate` shape the fee standard applies through
//! `fee::convert_amount`, so consumers reuse that arithmetic instead of restating it. The procedure
//! body only dispatches to a stored implementation root, which keeps its MAST root - the address
//! consumers resolve over FPI - stable while the pricing behind it changes.
//!
//! [`PriceFeed`] is one such implementation: published unit prices per faucet, all in a single
//! quote unit, divided into a rate. The quote cancels out of that division, so it never appears in
//! the interface.
//!
//! [`PriceReaderManager`] is the consuming side, and holds nothing but which oracle account to ask.
//! The oracle's procedure root is resolved at assembly time from the stable wrapper rather than
//! stored, so replacing an oracle's implementation never touches a consumer's storage.
//!
//! An asset the oracle cannot price yields `den = 0` rather than a failure, so a consumer valuing
//! many assets can decide what an unpriceable one means to it. Ignoring the case still fails
//! closed, because `fee::convert_amount` rejects a zero denominator. What to do about it, and how
//! stale a rate may be, are consumer policies and deliberately absent from this standard.

mod price_feed;
mod price_oracle;
mod price_reader;
mod types;

pub use price_feed::PriceFeed;
pub use price_oracle::PriceOracle;
pub use price_reader::PriceReaderManager;
pub use types::{ConversionRate, FeedPriceKey, PriceEntry, PriceOracleError, QuoteId};
