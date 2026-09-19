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
    #[error("a conversion rate must have both terms non-zero, or both zero to mean unpriced")]
    TermsPartiallyZero,
    #[error("cannot convert at a rate that prices nothing")]
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
/// Either both terms are non-zero or both are zero. Both zero means the oracle cannot price the
/// pair, including when its data is too stale to rely on. `fee::convert_amount` rejects a zero in
/// either term, so such a rate cannot be applied by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionRate {
    num: Felt,
    den: Felt,
}

impl ConversionRate {
    /// Constructs a rate from its numerator and denominator.
    ///
    /// # Errors
    ///
    /// Returns an error if exactly one of the terms is zero. A rate is either usable, with both
    /// terms non-zero, or unpriced, with both zero; one zero term describes neither.
    pub fn new(num: Felt, den: Felt) -> Result<Self, ConversionRateError> {
        if (num == Felt::ZERO) != (den == Felt::ZERO) {
            return Err(ConversionRateError::TermsPartiallyZero);
        }
        Ok(Self { num, den })
    }

    /// Returns the rate an oracle reports for a pair it cannot price.
    pub const fn unpriced() -> Self {
        Self { num: Felt::ZERO, den: Felt::ZERO }
    }

    /// Returns the numerator of the rate.
    pub const fn num(&self) -> Felt {
        self.num
    }

    /// Returns the denominator of the rate, which is zero exactly when the pair cannot be priced.
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
    /// Returns an error if the rate prices nothing, if the converted amount does not fit in a
    /// `u64`, or if it exceeds [`FungibleAsset::MAX_AMOUNT`].
    pub fn convert(
        &self,
        source: FungibleAsset,
        target_faucet_id: AccountId,
    ) -> Result<FungibleAsset, ConversionRateError> {
        if !self.is_priced() {
            return Err(ConversionRateError::RateUnpriced);
        }

        // both terms are non-zero here, since the constructor rejects a rate with only one zero
        let num = self.num.as_canonical_u64();
        let den = self.den.as_canonical_u64();
        let converted =
            (u128::from(source.amount().as_u64()) * u128::from(num)).div_ceil(u128::from(den));
        let converted = u64::try_from(converted)
            .map_err(|_| ConversionRateError::ConvertedAmountTooBig(converted))?;

        Ok(FungibleAsset::new(target_faucet_id, converted)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rate_with_one_zero_term_is_rejected() {
        assert!(matches!(
            ConversionRate::new(Felt::ZERO, Felt::ONE),
            Err(ConversionRateError::TermsPartiallyZero)
        ));
        assert!(matches!(
            ConversionRate::new(Felt::ONE, Felt::ZERO),
            Err(ConversionRateError::TermsPartiallyZero)
        ));
    }

    #[test]
    fn a_rate_is_either_usable_or_unpriced() {
        let usable = ConversionRate::new(Felt::from(3u32), Felt::from(2u32)).unwrap();
        assert!(usable.is_priced());

        let unpriced = ConversionRate::new(Felt::ZERO, Felt::ZERO).unwrap();
        assert!(!unpriced.is_priced());
        assert_eq!(unpriced, ConversionRate::unpriced());
    }

    #[test]
    fn converting_at_an_unpriced_rate_is_rejected() {
        let faucet_id = AccountId::try_from(
            miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        )
        .unwrap();
        let source = FungibleAsset::new(faucet_id, 10).unwrap();

        assert!(matches!(
            ConversionRate::unpriced().convert(source, faucet_id),
            Err(ConversionRateError::RateUnpriced)
        ));
    }

    #[test]
    fn converting_rounds_up_like_the_on_chain_path() {
        let source_faucet = AccountId::try_from(
            miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        )
        .unwrap();
        let target_faucet = AccountId::try_from(
            miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
        )
        .unwrap();

        // 10 * 1 / 3 is 3.33..., which rounds up to 4 as `fee::convert_amount` does
        let rate = ConversionRate::new(Felt::from(1u32), Felt::from(3u32)).unwrap();
        let converted = rate
            .convert(FungibleAsset::new(source_faucet, 10).unwrap(), target_faucet)
            .unwrap();

        assert_eq!(converted.faucet_id(), target_faucet);
        assert_eq!(converted.amount().as_u64(), 4);
    }
}
