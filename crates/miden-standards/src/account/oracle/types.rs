use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::errors::AssetError;

// ERRORS
// ================================================================================================

/// Errors that can occur when applying a [`ConversionRate`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConversionRateError {
    #[error("cannot convert at a rate whose numerator or denominator is zero")]
    RateUnpriced,
    #[error("converted amount {0} does not fit in a u64")]
    ConvertedAmountTooBig(u128),
    #[error("failed to build the converted asset")]
    Asset(#[from] AssetError),
}

// CONVERSION RATE
// ================================================================================================

/// The rate converting one asset into another, as returned by
/// [`PriceOracle`][crate::account::oracle::PriceOracle].
///
/// `amount` of the source asset is worth `ceil(amount * num / den)` of the target asset, matching
/// the `ConversionRate` the fee standard applies in `fee::convert_amount`.
///
/// `den = 0` means the oracle cannot price the pair, including when its data is too stale to rely
/// on. `num` is 0 as well in that case.
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

    /// Converts a fungible asset into one issued by `target_faucet_id` at this rate.
    ///
    /// The converted amount is `ceil(amount * num / den)`, which is what `fee::convert_amount`
    /// computes on chain, so both sides round the same way. The intermediate product is held in a
    /// `u128`, which cannot overflow because an asset amount and a rate term each fit in a `u64`.
    ///
    /// The target faucet is a parameter rather than part of the rate: a rate is a pure ratio and
    /// carries no asset identity, so the same one converts between any pair it was derived for.
    ///
    /// # Errors
    ///
    /// Returns an error if the rate cannot price the pair, if the converted amount does not fit in
    /// a `u64`, or if it exceeds [`FungibleAsset::MAX_AMOUNT`].
    pub fn convert(
        &self,
        source: FungibleAsset,
        target_faucet_id: AccountId,
    ) -> Result<FungibleAsset, ConversionRateError> {
        let num = self.num.as_canonical_u64();
        let den = self.den.as_canonical_u64();
        if num == 0 || den == 0 {
            return Err(ConversionRateError::RateUnpriced);
        }

        let converted =
            (u128::from(source.amount().as_u64()) * u128::from(num)).div_ceil(u128::from(den));
        let converted = u64::try_from(converted)
            .map_err(|_| ConversionRateError::ConvertedAmountTooBig(converted))?;

        Ok(FungibleAsset::new(target_faucet_id, converted)?)
    }
}
