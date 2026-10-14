use miden_verifier::{
    ExecutionClaim,
    ExecutionProof,
    PrecompileStatus,
    VerificationError,
    VerificationOutcome,
    Verifier,
};

use crate::PROTOCOL_PROOF_HASH;
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
    /// - The transaction proof contains settled precompile work.
    /// - The VM proof does not use the protocol's Eidos transcript hash.
    /// - Transaction verification fails.
    /// - A deferred precompile witness is invalid or does not match the VM proof.
    /// - The security level of the verified proof is insufficient.
    pub fn verify(
        &self,
        transaction: &ProvenTransaction,
    ) -> Result<VerificationOutcome, TransactionVerifierError> {
        validate_proof_shape(transaction.proof())?;

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
            .with_min_conjectured_security_level_per_stark(self.proof_security_level)
            .verify(&claim, transaction.proof())
            .map_err(|error| match error {
                VerificationError::InsufficientSecurityLevel { actual, required } => {
                    TransactionVerifierError::InsufficientProofSecurityLevel {
                        actual,
                        expected_minimum: required,
                    }
                },
                error => TransactionVerifierError::TransactionVerificationFailed(error),
            })?;

        Ok(outcome)
    }
}

/// Checks the transaction proof lifecycle and protocol transcript hash.
fn validate_proof_shape(proof: &ExecutionProof) -> Result<(), TransactionVerifierError> {
    if matches!(proof.precompile(), PrecompileStatus::Proven(_)) {
        return Err(TransactionVerifierError::TransactionProofContainsPrecompiles);
    }

    let vm_hash = proof.vm().proof.hash_fn();
    if vm_hash != PROTOCOL_PROOF_HASH {
        return Err(TransactionVerifierError::UnsupportedVmProofHash {
            actual: vm_hash,
            expected: PROTOCOL_PROOF_HASH,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_verifier::{HashFunction, StarkProof};

    use super::*;
    use crate::testing::{
        dummy_deferred_execution_proof,
        dummy_execution_proof,
        dummy_precompile_execution_proof,
    };

    #[test]
    fn proof_shape_requires_eidos_and_rejects_settled_precompiles() {
        assert_matches!(validate_proof_shape(&dummy_execution_proof()), Ok(()));
        assert_matches!(validate_proof_shape(&dummy_deferred_execution_proof()), Ok(()));
        assert_matches!(
            validate_proof_shape(&dummy_precompile_execution_proof()),
            Err(TransactionVerifierError::TransactionProofContainsPrecompiles)
        );

        let (compatibility, mut vm, precompile) = dummy_execution_proof().into_parts();
        vm.proof = StarkProof::new(Vec::new(), HashFunction::Blake3_256);
        let proof = ExecutionProof::from_parts(compatibility, vm, precompile);
        assert_matches!(
            validate_proof_shape(&proof),
            Err(TransactionVerifierError::UnsupportedVmProofHash {
                actual: HashFunction::Blake3_256,
                expected: PROTOCOL_PROOF_HASH,
            })
        );
    }
}
