//! Price oracle standards: publishing unit prices and valuing assets against them.
//!
//! The standard splits the two sides of a price feed:
//!
//! - [`PriceFeed`] is the publishing side. It stores a unit price per faucet, all denominated in a
//!   single quote unit fixed at deployment, and exposes them over FPI. It never sees an asset
//!   amount, so consumers that scale differently can share one feed.
//! - [`PriceReaderManager`] is the consuming side. It owns the configuration - which feed, which
//!   quote unit, at what exponent, with what staleness bound - and other components installed on
//!   the same account value assets through its `quote_asset_value` procedure.
//!
//! Staleness is bounded on both sides, because the two guard different failures. The feed applies
//! its own transaction expiration delta, which bounds how far the transaction's reference block may
//! lag; the reader checks the price's timestamp against a configurable maximum age, which bounds
//! how long ago the feed last published. A fresh reference block says nothing about a feed that
//! stopped updating, and a third-party feed cannot be assumed to set a delta at all.

mod config;
mod price_feed;
mod price_reader;
mod types;

pub use config::{PriceReaderConfig, PriceReaderConfigBuilder};
pub use price_feed::PriceFeed;
pub use price_reader::PriceReaderManager;
pub use types::{FeedPriceKey, PriceEntry, PriceOracleError, QuoteId, UntrackedAssetPolicy};
