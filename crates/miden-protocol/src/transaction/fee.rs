use crate::MAX_TX_EXECUTION_CYCLES;
use crate::asset::AssetAmount;
use crate::block::FeeParameters;
use crate::errors::AssetError;

// TRANSACTION FEE
// ================================================================================================

/// Errors from constructing [`TransactionFee`] inputs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransactionFeeError {
    /// The total cycle count was zero; every transaction executes at least the kernel prologue.
    #[error("transaction fee inputs require a non-zero total cycle count")]
    ZeroTotalCycles,
    /// The total cycle count exceeds [`MAX_TX_EXECUTION_CYCLES`], the bound the kernel's
    /// `compute_fee` enforces.
    #[error("total cycle count {0} exceeds the maximum of {MAX_TX_EXECUTION_CYCLES} cycles")]
    TotalCyclesExceedsMax(u32),
    /// The computed fee exceeds the maximum representable asset amount.
    #[error("computed fee exceeds the maximum asset amount")]
    FeeExceedsMaxAssetAmount(#[source] AssetError),
}

/// The inputs from which a transaction's fee is computed, mirroring the transaction kernel's
/// `compute_fee` procedure.
///
/// This is the single Rust implementation of the kernel fee formula: keep it in sync with
/// `compute_fee` in `asm/kernels/transaction-core/src/tx.masm`. The kernel's output-notes fee
/// term is currently hardcoded to zero and thus omitted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionFee {
    log_verification_cycles: u32,
}

impl TransactionFee {
    /// Creates the fee inputs for a transaction executing `total_cycles` VM cycles.
    ///
    /// Mirrors the kernel's `compute_fee`: the number of charged verification cycles is
    /// `ilog2(total_cycles) + 1`, where the unconditional `+ 1` rounds the proof-verification
    /// cost up to the next power of two.
    ///
    /// Returns an error if `total_cycles` is 0 (every transaction executes at least the kernel
    /// prologue, so a zero cycle count cannot describe a transaction) or exceeds
    /// [`MAX_TX_EXECUTION_CYCLES`], the bound the kernel's `compute_fee` enforces.
    pub fn new(total_cycles: u32) -> Result<Self, TransactionFeeError> {
        if total_cycles == 0 {
            return Err(TransactionFeeError::ZeroTotalCycles);
        }
        if total_cycles > MAX_TX_EXECUTION_CYCLES {
            return Err(TransactionFeeError::TotalCyclesExceedsMax(total_cycles));
        }
        Ok(Self {
            log_verification_cycles: total_cycles.ilog2() + 1,
        })
    }

    /// Returns the number of verification cycles the fee is charged for - a logarithmic
    /// measure of the transaction's total cycle count, not an exact cycle count.
    pub fn log_verification_cycles(&self) -> u32 {
        self.log_verification_cycles
    }

    /// Returns fee inputs charging `extra_verification_cycles` on top of the formula's
    /// verification cycles, e.g. as a safety margin when the fee is derived from an estimated
    /// rather than a measured cycle count.
    ///
    /// The addition saturates at `u32::MAX` verification cycles; a fee that large is rejected
    /// by [`Self::compute_fee`] for any base fee above `2^31`.
    pub fn with_safety_margin(self, extra_verification_cycles: u32) -> Self {
        Self {
            log_verification_cycles: self
                .log_verification_cycles
                .saturating_add(extra_verification_cycles),
        }
    }

    /// Computes the fee under the given fee parameters.
    ///
    /// Returns an error if the fee exceeds [`AssetAmount::MAX`]: the formula's own
    /// verification cycles keep the fee far below it, but a large [`Self::with_safety_margin`]
    /// can push it beyond.
    pub fn compute_fee(
        &self,
        fee_parameters: &FeeParameters,
    ) -> Result<AssetAmount, TransactionFeeError> {
        // Multiply in u64: the kernel multiplies in the field, so a u32 product would wrap
        // where the kernel does not. A product of two u32 values cannot wrap a u64.
        let fee_amount = u64::from(fee_parameters.verification_base_fee())
            * u64::from(self.log_verification_cycles);

        AssetAmount::new(fee_amount).map_err(TransactionFeeError::FeeExceedsMaxAssetAmount)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_verification_cycles_formula() {
        let log_verification_cycles = |total_cycles: u32| {
            TransactionFee::new(total_cycles).unwrap().log_verification_cycles()
        };
        assert_eq!(log_verification_cycles(1), 1);
        assert_eq!(log_verification_cycles(2), 2);
        assert_eq!(log_verification_cycles(3), 2);
        assert_eq!(log_verification_cycles(4), 3);
        assert_eq!(log_verification_cycles(65_536), 17);
        assert_eq!(log_verification_cycles(MAX_TX_EXECUTION_CYCLES), 30);
    }

    #[test]
    fn zero_cycles_are_rejected() {
        assert!(matches!(TransactionFee::new(0), Err(TransactionFeeError::ZeroTotalCycles)));
    }

    #[test]
    fn cycles_above_the_kernel_maximum_are_rejected() {
        assert!(matches!(
            TransactionFee::new(MAX_TX_EXECUTION_CYCLES + 1),
            Err(TransactionFeeError::TotalCyclesExceedsMax(_))
        ));
    }

    /// The maximal margin-free fee (`u32::MAX` base fee, 30 verification cycles) must neither
    /// wrap nor exceed `AssetAmount::MAX`.
    #[test]
    fn compute_fee_does_not_wrap_at_the_maximal_base_fee() {
        let fee = TransactionFee::new(MAX_TX_EXECUTION_CYCLES)
            .unwrap()
            .compute_fee(&FeeParameters::new(u32::MAX))
            .unwrap();
        assert_eq!(fee.as_u64(), u64::from(u32::MAX) * 30);
    }

    /// The safety margin adds verification cycles before the base-fee multiplication.
    #[test]
    fn safety_margin_adds_verification_cycles() {
        let fee = TransactionFee::new(1 << 16)
            .unwrap()
            .with_safety_margin(3)
            .compute_fee(&FeeParameters::new(500))
            .unwrap();
        assert_eq!(fee.as_u64(), 500 * (17 + 3));
    }

    /// An oversized margin pushes the fee beyond `AssetAmount::MAX`, which `compute_fee`
    /// rejects.
    #[test]
    fn fee_exceeding_max_asset_amount_is_rejected() {
        let result = TransactionFee::new(1)
            .unwrap()
            .with_safety_margin(u32::MAX - 1)
            .compute_fee(&FeeParameters::new(u32::MAX));
        assert!(matches!(result, Err(TransactionFeeError::FeeExceedsMaxAssetAmount(_))));
    }
}
