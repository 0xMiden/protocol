use miden_protocol::batch::{BatchKernel, BatchOutputs, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::vm::ProgramInfo;
use miden_protocol::{Word, verify_execution_proof};
use miden_verifier::{ExecutionClaim, ExecutionProof};

use crate::BatchVerifierError;

// BATCH VERIFIER
// ================================================================================================

/// The [`BatchVerifier`] verifies the execution proof attached to a [`ProvenBatch`] against the
/// batch kernel program.
///
/// The `proof_security_level` specifies the minimum security level (in bits) the batch proof must
/// have to be considered valid.
///
/// # Warning
///
/// The current batch kernel is a skeleton that drops its inputs and emits an all-zero output
/// region, so a successful [`verify`](BatchVerifier::verify) attests only that the kernel program
/// ran over the batch's `[BLOCK_COMMITMENT, BATCH_ID]` public inputs. It does **not** yet bind the
/// batch's notes, account updates, or expiration: those values are not part of what the proof
/// commits to, so a `ProvenBatch` whose contents were mutated would still verify. This verifier
/// must therefore not be relied on at a trust boundary until the kernel verification logic that
/// emits and binds the real commitments lands.
///
/// The proof also does not cover the precompile claims of the batch's transactions.
pub struct BatchVerifier {
    batch_program_info: ProgramInfo,
    proof_security_level: u32,
}

impl BatchVerifier {
    /// Returns a new [`BatchVerifier`] instantiated with the specified minimum security level.
    pub fn new(proof_security_level: u32) -> Self {
        let batch_program_info = BatchKernel::program_info();
        Self { batch_program_info, proof_security_level }
    }

    /// Verifies the provided [`ProvenBatch`]'s execution proof against the batch kernel.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The batch proof contains precompile work.
    /// - The VM proof does not use the protocol's Eidos transcript hash.
    /// - Batch proof verification fails.
    /// - The security level of the verified proof is insufficient.
    pub fn verify(&self, batch: &ProvenBatch) -> Result<(), BatchVerifierError> {
        validate_proof_shape(batch.proof())?;

        let stack_inputs =
            BatchKernel::build_input_stack(batch.reference_block_commitment(), batch.id());

        // The skeleton kernel drops its inputs and emits the all-zero output region, so the proof
        // attests to empty outputs. Once the kernel computes the real commitments, these empty
        // values become `batch.input_notes().commitment()`, the batch note tree root and
        // `batch.batch_expiration_block_num()`.
        let stack_outputs =
            BatchOutputs::new(Word::empty(), Word::empty(), BlockNumber::from(0u32))
                .into_stack_outputs();

        let claim = ExecutionClaim::from_program_info(
            self.batch_program_info.clone(),
            stack_inputs,
            stack_outputs,
        );
        let outcome = verify_execution_proof(&claim, batch.proof(), self.proof_security_level)?;
        if !outcome.is_complete() {
            return Err(BatchVerifierError::IncompleteProof);
        }

        Ok(())
    }
}

/// Checks that the proof has no precompile work.
fn validate_proof_shape(proof: &ExecutionProof) -> Result<(), BatchVerifierError> {
    if proof.has_precompiles() {
        return Err(BatchVerifierError::BatchProofContainsPrecompiles);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use miden_protocol::testing::{
        dummy_deferred_execution_proof,
        dummy_execution_proof,
        dummy_precompile_execution_proof,
    };

    use super::*;

    #[test]
    fn proof_shape_rejects_precompile_work() {
        assert!(matches!(
            validate_proof_shape(&dummy_deferred_execution_proof()),
            Err(BatchVerifierError::BatchProofContainsPrecompiles)
        ));

        assert!(matches!(
            validate_proof_shape(&dummy_precompile_execution_proof()),
            Err(BatchVerifierError::BatchProofContainsPrecompiles)
        ));

        assert!(validate_proof_shape(&dummy_execution_proof()).is_ok());
    }
}
