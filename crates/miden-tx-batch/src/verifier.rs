use miden_protocol::batch::{BatchKernel, BatchOutputs, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::vm::ProgramInfo;
use miden_protocol::{PROTOCOL_PROOF_HASH, Word};
use miden_verifier::{ExecutionClaim, ExecutionProof, VerificationError, Verifier};

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
        let outcome = Verifier::new()
            .with_min_conjectured_security_level_per_stark(self.proof_security_level)
            .verify(&claim, batch.proof())
            .map_err(|error| match error {
                VerificationError::InsufficientSecurityLevel { actual, required } => {
                    BatchVerifierError::InsufficientProofSecurityLevel {
                        actual,
                        expected_minimum: required,
                    }
                },
                error => BatchVerifierError::BatchVerificationFailed(error),
            })?;
        if !outcome.is_complete() {
            return Err(BatchVerifierError::IncompleteProof);
        }

        Ok(())
    }
}

/// Checks that the proof has no precompile work and uses the protocol transcript hash.
fn validate_proof_shape(proof: &ExecutionProof) -> Result<(), BatchVerifierError> {
    if proof.has_precompiles() {
        return Err(BatchVerifierError::BatchProofContainsPrecompiles);
    }

    let vm_hash = proof.vm().proof.hash_fn();
    if vm_hash != PROTOCOL_PROOF_HASH {
        return Err(BatchVerifierError::UnsupportedVmProofHash {
            actual: vm_hash,
            expected: PROTOCOL_PROOF_HASH,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_protocol::testing::{
        dummy_deferred_execution_proof,
        dummy_execution_proof,
        dummy_precompile_execution_proof,
    };
    use miden_verifier::{HashFunction, StarkProof};

    use super::*;

    #[test]
    fn proof_shape_requires_complete_eidos_proofs() {
        assert!(matches!(
            validate_proof_shape(&dummy_deferred_execution_proof()),
            Err(BatchVerifierError::BatchProofContainsPrecompiles)
        ));

        assert!(matches!(
            validate_proof_shape(&dummy_precompile_execution_proof()),
            Err(BatchVerifierError::BatchProofContainsPrecompiles)
        ));

        let (compatibility, mut vm, precompile) = dummy_execution_proof().into_parts();
        vm.proof = StarkProof::new(Vec::new(), HashFunction::Blake3_256);
        let blake3_vm = ExecutionProof::from_parts(compatibility, vm, precompile);
        assert!(matches!(
            validate_proof_shape(&blake3_vm),
            Err(BatchVerifierError::UnsupportedVmProofHash {
                actual: HashFunction::Blake3_256,
                expected: PROTOCOL_PROOF_HASH,
            })
        ));

        assert!(validate_proof_shape(&dummy_execution_proof()).is_ok());
    }
}
