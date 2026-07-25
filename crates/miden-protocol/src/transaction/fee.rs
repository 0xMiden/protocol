use crate::asset::AssetAmount;
use crate::block::FeeParameters;

// TRANSACTION FEE
// ================================================================================================

/// Errors from constructing [`TransactionFee`] inputs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransactionFeeError {
    /// The total cycle count was zero; every transaction executes at least the kernel prologue.
    #[error("transaction fee inputs require a non-zero total cycle count")]
    ZeroTotalCycles,
}

/// The inputs from which a transaction's fee is computed, mirroring the transaction kernel's
/// `compute_fee` procedure.
///
/// This is the single Rust implementation of the kernel fee formula: keep it in sync with
/// `compute_fee` in `asm/kernels/transaction-core/src/tx.masm`. The kernel formula also
/// contains an output-notes fee term, which the kernel currently hardcodes to zero and this
/// type therefore omits. The kernel tests in `miden-testing` pin that zero behaviorally
/// (`compute_fee_accepts_sorted_in_bounds_exclude_notes` executes `compute_fee` with output
/// notes and asserts the fee is verification-only), so implementing the term fails that test -
/// grow this type along with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionFee {
    verification_cycles: u32,
}

impl TransactionFee {
    /// Creates the fee inputs for a transaction executing `total_cycles` VM cycles.
    ///
    /// Mirrors the kernel's `compute_fee`: the number of verification cycles is
    /// `ilog2(total_cycles) + 1`, where the unconditional `+ 1` rounds the proof-verification
    /// cost up to the next power of two (at an exact power of two it adds one full extra
    /// cycle, exactly as the kernel does).
    ///
    /// Returns an error if `total_cycles` is 0: every transaction executes at least the kernel
    /// prologue, so a zero cycle count cannot describe a transaction. The kernel additionally
    /// rejects transactions above its `MAX_CYCLES` bound; this type accepts any non-zero
    /// count.
    pub fn new(total_cycles: u32) -> Result<Self, TransactionFeeError> {
        if total_cycles == 0 {
            return Err(TransactionFeeError::ZeroTotalCycles);
        }
        Ok(Self {
            verification_cycles: total_cycles.ilog2() + 1,
        })
    }

    /// Returns the number of verification cycles the fee is charged for.
    pub fn verification_cycles(&self) -> u32 {
        self.verification_cycles
    }

    /// Computes the fee under the given fee parameters.
    pub fn compute_fee(&self, fee_parameters: &FeeParameters) -> AssetAmount {
        // Multiply in u64: the kernel multiplies in the field, so a u32 product would wrap
        // where the kernel does not. The product is at most `u32::MAX * 32`, far below
        // `AssetAmount::MAX`.
        let fee_amount =
            u64::from(fee_parameters.verification_base_fee()) * u64::from(self.verification_cycles);

        AssetAmount::new(fee_amount).expect("fee is bounded far below AssetAmount::MAX")
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountId;
    use crate::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    fn fee_parameters(verification_base_fee: u32) -> FeeParameters {
        let fee_faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)
            .expect("testing faucet ID should be valid");
        FeeParameters::new(fee_faucet_id, verification_base_fee)
    }

    /// The `+ 1` is unconditional, also at exact powers of two - mirroring the kernel's
    /// `ilog2 add.1`.
    #[test]
    fn verification_cycles_match_the_kernel_formula() {
        let verification_cycles =
            |total_cycles: u32| TransactionFee::new(total_cycles).unwrap().verification_cycles();
        assert_eq!(verification_cycles(1), 1);
        assert_eq!(verification_cycles(2), 2);
        assert_eq!(verification_cycles(3), 2);
        assert_eq!(verification_cycles(4), 3);
        assert_eq!(verification_cycles(65_536), 17);
        assert_eq!(verification_cycles(u32::MAX), 32);
    }

    #[test]
    fn zero_cycles_are_rejected() {
        assert!(matches!(TransactionFee::new(0), Err(TransactionFeeError::ZeroTotalCycles)));
    }

    /// The maximal fee (`u32::MAX` base fee, 32 verification cycles) must neither wrap nor
    /// exceed `AssetAmount::MAX`.
    #[test]
    fn compute_fee_does_not_wrap_at_the_maximal_base_fee() {
        let fee = TransactionFee::new(u32::MAX).unwrap().compute_fee(&fee_parameters(u32::MAX));
        assert_eq!(fee.as_u64(), u64::from(u32::MAX) * 32);
    }
}
