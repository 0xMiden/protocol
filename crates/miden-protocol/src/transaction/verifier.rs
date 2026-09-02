use alloc::sync::Arc;

use miden_core::deferred::{DeferredRoot, DeferredState, DeferredStateWire};
use miden_verifier::{ExecutionClaim, ExecutionProof, VerificationOutcome, Verifier};

use crate::errors::TransactionVerifierError;
use crate::transaction::{ProvenTransaction, TransactionKernel};
use crate::vm::ProgramInfo;

// TRANSACTION VERIFIER
// ================================================================================================

/// The [TransactionVerifier] is used to verify  [ProvenTransaction]s.
///
/// The [TransactionVerifier] contains a [ProgramInfo] object which is associated with the
/// transaction kernel program.  The `proof_security_level` specifies the minimum security
/// level that the transaction proof must have in order to be considered valid.
pub struct TransactionVerifier {
    tx_program_info: ProgramInfo,
    proof_security_level: u32,
}

impl TransactionVerifier {
    /// Returns a new [TransactionVerifier] instantiated with the specified security level.
    pub fn new(proof_security_level: u32) -> Self {
        let tx_program_info = TransactionKernel::program_info();
        Self { tx_program_info, proof_security_level }
    }

    /// Verifies the provided [`ProvenTransaction`] against the transaction kernel and returns its
    /// verification outcome.
    ///
    /// A verified transaction may still have an outstanding precompile obligation. Callers must
    /// inspect the returned [`VerificationOutcome`] and handle that obligation if present.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The proof contains settled precompile work.
    /// - Transaction verification fails.
    /// - A deferred precompile witness is invalid or does not match the VM proof.
    /// - The security level of the verified proof is insufficient.
    pub fn verify(
        &self,
        transaction: &ProvenTransaction,
    ) -> Result<VerificationOutcome, TransactionVerifierError> {
        if matches!(transaction.proof(), ExecutionProof::Complete { precompile: Some(_), .. }) {
            return Err(TransactionVerifierError::TransactionProofContainsPrecompiles);
        }

        // build stack inputs and outputs
        let stack_inputs = TransactionKernel::build_input_stack(
            transaction.account_id(),
            transaction.account_update().initial_state_commitment(),
            transaction.input_notes().commitment(),
            transaction.ref_block_commitment(),
            transaction.ref_block_num(),
        );
        let stack_outputs = TransactionKernel::build_output_stack(
            transaction.account_update().final_state_commitment(),
            transaction.account_update().account_patch_commitment(),
            transaction.output_notes().commitment(),
            transaction.expiration_block_num(),
        );

        // verify transaction proof
        let claim = ExecutionClaim::from_program_info(
            self.tx_program_info.clone(),
            stack_inputs,
            stack_outputs,
        );
        let outcome = Verifier::new()
            .verify(&claim, transaction.proof())
            .map_err(TransactionVerifierError::TransactionVerificationFailed)?;
        let proof_security_level = outcome.security_level();

        if let ExecutionProof::Deferred { precompile, .. } = transaction.proof() {
            let expected_root = outcome
                .outstanding_precompile_root()
                .expect("a verified deferred proof must have an outstanding precompile root");
            validate_deferred_witness(precompile, expected_root)?;
        }

        // check security level
        if proof_security_level < self.proof_security_level {
            return Err(TransactionVerifierError::InsufficientProofSecurityLevel {
                actual: proof_security_level,
                expected_minimum: self.proof_security_level,
            });
        }

        Ok(outcome)
    }
}

fn validate_deferred_witness(
    witness: &DeferredStateWire,
    expected_root: DeferredRoot,
) -> Result<(), TransactionVerifierError> {
    let state = DeferredState::from_wire(Arc::new(miden_precompiles::registry()), witness)
        .map_err(TransactionVerifierError::InvalidTransactionPrecompileWitness)?;
    let actual_root = state.root();

    if actual_root != expected_root {
        return Err(TransactionVerifierError::TransactionPrecompileRootMismatch {
            expected: expected_root,
            actual: actual_root,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use miden_core::Word;
    use miden_core::deferred::DeferredStateWire;

    use super::validate_deferred_witness;
    use crate::errors::TransactionVerifierError;

    #[test]
    fn rejects_a_deferred_witness_with_the_wrong_root() {
        let expected_root = Word::from([1_u32, 2, 3, 4]);
        let error =
            validate_deferred_witness(&DeferredStateWire::default(), expected_root).unwrap_err();

        assert!(matches!(
            error,
            TransactionVerifierError::TransactionPrecompileRootMismatch { .. }
        ));
    }
}
