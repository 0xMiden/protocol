use miden_protocol::account::AccountId;
use miden_protocol::{Felt, Word};

// ERRORS
// ================================================================================================

/// Errors that can occur when building price oracle values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PriceOracleError {
    #[error("quote symbol must be between 1 and {max} ASCII characters", max = QuoteId::MAX_SYMBOL_LEN)]
    QuoteSymbolLength,
    #[error("quote symbol must contain only ASCII characters")]
    QuoteSymbolNotAscii,
    #[error("untracked asset policy must be 0 (omit) or 1 (reject), got {0}")]
    UntrackedAssetPolicyInvalid(u64),
    #[error("published price must be non-zero")]
    PriceZero,
}

// QUOTE ID
// ================================================================================================

/// Identifies the unit a [`PriceFeed`][crate::account::oracle::PriceFeed] quotes its prices in.
///
/// This is an opaque word rather than an [`AccountId`]: quote units such as USD have no faucet on
/// Miden, so there is no account to point at. [`QuoteId::from_symbol`] packs a short ASCII ticker
/// into that word for the common case; [`QuoteId::new`] accepts any word for the rest, including
/// the id of an on-chain faucet when prices are quoted in a stablecoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuoteId(Word);

impl QuoteId {
    /// The maximum number of ASCII characters [`QuoteId::from_symbol`] accepts.
    pub const MAX_SYMBOL_LEN: usize = 8;

    /// Constructs a quote id from an arbitrary word.
    pub const fn new(word: Word) -> Self {
        Self(word)
    }

    /// Constructs a quote id from a short ASCII ticker such as `"USD"`.
    ///
    /// The characters are packed little-endian into the first felt of the word; the remaining felts
    /// are zero. The packing is total for the accepted lengths, so distinct symbols always yield
    /// distinct quote ids.
    ///
    /// # Errors
    ///
    /// Returns an error if the symbol is empty, longer than [`QuoteId::MAX_SYMBOL_LEN`], or
    /// contains a non-ASCII character.
    pub fn from_symbol(symbol: &str) -> Result<Self, PriceOracleError> {
        if symbol.is_empty() || symbol.len() > Self::MAX_SYMBOL_LEN {
            return Err(PriceOracleError::QuoteSymbolLength);
        }
        if !symbol.is_ascii() {
            return Err(PriceOracleError::QuoteSymbolNotAscii);
        }

        // The packed value uses at most 7 of the 8 bytes' worth of headroom below the field
        // modulus in the worst case, because ASCII bytes never set the high bit of the last byte.
        let packed = symbol
            .bytes()
            .enumerate()
            .fold(0u64, |acc, (i, byte)| acc | ((byte as u64) << (i * 8)));

        Ok(Self(Word::new([
            Felt::new(packed).expect("packed ASCII bytes always fit in the field"),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ])))
    }

    /// Returns the quote id as a [`Word`].
    pub const fn as_word(&self) -> Word {
        self.0
    }
}

impl From<Word> for QuoteId {
    fn from(word: Word) -> Self {
        Self(word)
    }
}

impl From<QuoteId> for Word {
    fn from(quote_id: QuoteId) -> Self {
        quote_id.0
    }
}

// FEED PRICE KEY
// ================================================================================================

/// The key a [`PriceFeed`][crate::account::oracle::PriceFeed] publishes an asset's price under.
///
/// The standard feed is keyed by faucet id, which is what [`FeedPriceKey::from_faucet_id`]
/// produces and what the reader falls back to when no override is configured. Feeds that publish
/// under their own identifiers are supported by mapping a faucet id to an arbitrary key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeedPriceKey(Word);

impl FeedPriceKey {
    /// Constructs a feed price key from an arbitrary word.
    pub const fn new(word: Word) -> Self {
        Self(word)
    }

    /// Constructs the canonical `[prefix, suffix, 0, 0]` key of the given faucet.
    pub fn from_faucet_id(faucet_id: AccountId) -> Self {
        Self(Word::new([
            faucet_id.prefix().as_felt(),
            faucet_id.suffix(),
            Felt::ZERO,
            Felt::ZERO,
        ]))
    }

    /// Returns the feed price key as a [`Word`].
    pub const fn as_word(&self) -> Word {
        self.0
    }
}

impl From<AccountId> for FeedPriceKey {
    fn from(faucet_id: AccountId) -> Self {
        Self::from_faucet_id(faucet_id)
    }
}

impl From<FeedPriceKey> for Word {
    fn from(key: FeedPriceKey) -> Self {
        key.0
    }
}

// UNTRACKED ASSET POLICY
// ================================================================================================

/// How the price reader treats an asset the configured feed publishes no price for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum UntrackedAssetPolicy {
    /// Report the asset as untracked and value it at zero (fail-open).
    #[default]
    Omit,
    /// Reject the transaction (fail-closed).
    Reject,
}

impl UntrackedAssetPolicy {
    /// Returns the policy's on-chain encoding.
    pub const fn as_felt(&self) -> Felt {
        match self {
            Self::Omit => Felt::ZERO,
            Self::Reject => Felt::ONE,
        }
    }

    /// Constructs a policy from its on-chain encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is neither `0` nor `1`.
    pub fn try_from_felt(value: Felt) -> Result<Self, PriceOracleError> {
        match value.as_canonical_u64() {
            0 => Ok(Self::Omit),
            1 => Ok(Self::Reject),
            other => Err(PriceOracleError::UntrackedAssetPolicyInvalid(other)),
        }
    }
}

// PRICE ENTRY
// ================================================================================================

/// A price published by a [`PriceFeed`][crate::account::oracle::PriceFeed].
///
/// The real value of one unit of the priced asset is `price * 10^(-exponent)`, expressed in the
/// feed's quote unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceEntry {
    price: Felt,
    exponent: u32,
    timestamp: u32,
}

impl PriceEntry {
    /// Constructs a price entry.
    ///
    /// # Errors
    ///
    /// Returns an error if `price` is zero, which the feed reserves to mean "not tracked".
    pub fn new(price: Felt, exponent: u32, timestamp: u32) -> Result<Self, PriceOracleError> {
        if price == Felt::ZERO {
            return Err(PriceOracleError::PriceZero);
        }
        Ok(Self { price, exponent, timestamp })
    }

    /// Returns the price of one unit of the asset, scaled by [`PriceEntry::exponent`].
    pub const fn price(&self) -> Felt {
        self.price
    }

    /// Returns the decimal exponent of [`PriceEntry::price`].
    pub const fn exponent(&self) -> u32 {
        self.exponent
    }

    /// Returns the block timestamp, in seconds, at which the price was observed.
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns the entry's storage value word `[price, exponent, timestamp, 0]`.
    pub fn to_word(self) -> Word {
        Word::new([self.price, Felt::from(self.exponent), Felt::from(self.timestamp), Felt::ZERO])
    }
}
