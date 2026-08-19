use miden_protocol::{Felt, Word};

// CONVERSION RATE
// ================================================================================================

/// The rate converting one asset into another, as returned by
/// [`PriceOracle`][crate::account::oracle::PriceOracle].
///
/// `amount` of the source asset is worth `ceil(amount * num / den)` of the target asset, matching
/// the `ConversionRate` the fee standard applies in `fee::convert_amount`.
///
/// A rate with `den == 0` means the oracle cannot price the pair. It is a value rather than a
/// failure so a caller valuing many assets can decide what an unpriceable one means to it; passing
/// such a rate to `fee::convert_amount` aborts, so overlooking the case still fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionRate {
    num: Felt,
    den: Felt,
    timestamp: u32,
}

impl ConversionRate {
    /// Constructs a rate from its numerator, denominator and freshness.
    pub const fn new(num: Felt, den: Felt, timestamp: u32) -> Self {
        Self { num, den, timestamp }
    }

    /// Returns the rate an oracle reports for a pair it cannot price.
    pub const fn unpriced() -> Self {
        Self {
            num: Felt::ZERO,
            den: Felt::ZERO,
            timestamp: 0,
        }
    }

    /// Returns the numerator of the rate.
    pub const fn num(&self) -> Felt {
        self.num
    }

    /// Returns the denominator of the rate, which is zero when the pair cannot be priced.
    pub const fn den(&self) -> Felt {
        self.den
    }

    /// Returns the block timestamp, in seconds, of the stalest input the rate was derived from.
    ///
    /// A rate derived from several prices is only as fresh as its stalest one, so a caller
    /// enforcing a maximum age compares against this rather than against any single input.
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns whether the oracle could price the pair.
    pub fn is_priced(&self) -> bool {
        self.den != Felt::ZERO
    }

    /// Returns the rate as the operand stack layout `[num, den, timestamp, 0]`.
    pub fn to_word(self) -> Word {
        Word::new([self.num, self.den, Felt::from(self.timestamp), Felt::ZERO])
    }
}
