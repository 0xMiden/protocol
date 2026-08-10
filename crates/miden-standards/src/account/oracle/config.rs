use alloc::collections::BTreeMap;

use miden_protocol::account::{AccountId, AccountProcedureRoot};

use super::types::{FeedPriceKey, QuoteId, UntrackedAssetPolicy};

// PRICE READER CONFIG
// ================================================================================================

/// Configuration of the price reader installed on an account.
///
/// A reader that is left without a feed cannot value anything: every read fails with
/// `price feed account is not configured`. Both [`PriceReaderConfig::feed_account_id`] and
/// [`PriceReaderConfig::get_price_proc_root`] are therefore optional at construction only so an
/// account can be deployed before its feed exists, and wired up afterwards through
/// `configure_feed`.
///
/// [`PriceReaderConfig::quote_exponent`] fixes the scale every quoted value is normalized to, so
/// values coming from feeds with different exponents remain summable. Any threshold compared
/// against a quoted value must be expressed at the same exponent.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct PriceReaderConfig {
    /// Account id of the price feed to read from.
    feed_account_id: Option<AccountId>,

    /// Procedure root of the feed's `get_price`, invoked over FPI.
    get_price_proc_root: Option<AccountProcedureRoot>,

    /// Unit the feed is expected to quote its prices in.
    quote_id: QuoteId,

    /// Decimal exponent every quoted value is normalized to.
    quote_exponent: u32,

    /// Largest accepted age, in seconds, of a price returned by the feed.
    ///
    /// This is the reader's own staleness bound. It is enforced in addition to, not instead of,
    /// the transaction expiration delta the feed applies: the delta bounds how far the reference
    /// block may lag, while this bounds how long ago the feed last published.
    max_age_secs: u32,

    /// How to treat an asset the feed publishes no price for.
    #[builder(default = UntrackedAssetPolicy::Omit)]
    untracked_policy: UntrackedAssetPolicy,

    /// Keys the feed publishes prices under, for feeds that do not key by faucet id.
    ///
    /// A faucet absent from this map is looked up under its own id, which is what the standard
    /// [`PriceFeed`][crate::account::oracle::PriceFeed] expects.
    #[builder(default)]
    feed_price_keys: BTreeMap<AccountId, FeedPriceKey>,
}

impl PriceReaderConfig {
    /// Returns the configured feed account id, or `None` when no feed is attached yet.
    pub const fn feed_account_id(&self) -> Option<AccountId> {
        self.feed_account_id
    }

    /// Returns the procedure root of the feed's `get_price`, or `None` when no feed is attached
    /// yet.
    pub const fn get_price_proc_root(&self) -> Option<AccountProcedureRoot> {
        self.get_price_proc_root
    }

    /// Returns the unit the feed is expected to quote its prices in.
    pub const fn quote_id(&self) -> QuoteId {
        self.quote_id
    }

    /// Returns the decimal exponent every quoted value is normalized to.
    pub const fn quote_exponent(&self) -> u32 {
        self.quote_exponent
    }

    /// Returns the largest accepted age, in seconds, of a price returned by the feed.
    pub const fn max_age_secs(&self) -> u32 {
        self.max_age_secs
    }

    /// Returns how an asset the feed publishes no price for is treated.
    pub const fn untracked_policy(&self) -> UntrackedAssetPolicy {
        self.untracked_policy
    }

    /// Returns the keys the feed publishes prices under, for feeds that do not key by faucet id.
    pub const fn feed_price_keys(&self) -> &BTreeMap<AccountId, FeedPriceKey> {
        &self.feed_price_keys
    }
}
