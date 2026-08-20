use miden_protocol::{Felt, Word};

// CONVERSION RATE
// ================================================================================================

/// The rate converting one asset into another, as returned by
/// [`PriceOracle`][crate::account::oracle::PriceOracle].
///
/// `amount` of the source asset is worth `ceil(amount * num / den)` of the target asset, matching
/// the `ConversionRate` the fee standard applies in `fee::convert_amount`.
///
/// A rate with `den == 0` means the oracle cannot price the pair, whether because it has no data
/// for it or because the data it has is too old to rely on. It is a value rather than a failure so
/// a caller valuing many assets can decide what an unpriceable one means to it; passing such a rate
/// to `fee::convert_amount` aborts, so overlooking the case still fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionRate {
    num: Felt,
    den: Felt,
}

impl ConversionRate {
    /// Constructs a rate from its numerator and denominator.
    pub const fn new(num: Felt, den: Felt) -> Self {
        Self { num, den }
    }

    /// Returns the rate an oracle reports for a pair it cannot price.
    pub const fn unpriced() -> Self {
        Self { num: Felt::ZERO, den: Felt::ZERO }
    }

    /// Returns the numerator of the rate.
    pub const fn num(&self) -> Felt {
        self.num
    }

    /// Returns the denominator of the rate, which is zero when the pair cannot be priced.
    pub const fn den(&self) -> Felt {
        self.den
    }

    /// Returns whether the oracle could price the pair.
    pub fn is_priced(&self) -> bool {
        self.den != Felt::ZERO
    }

    /// Returns the rate as the operand stack layout `[num, den, 0, 0]`.
    pub fn to_word(self) -> Word {
        Word::new([self.num, self.den, Felt::ZERO, Felt::ZERO])
    }
}
