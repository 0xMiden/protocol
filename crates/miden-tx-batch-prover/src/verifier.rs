use miden_protocol::Word;
use miden_protocol::batch::{BatchKernel, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::vm::ProgramInfo;
use miden_verifier::verify;

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
    /// - Batch proof verification fails.
    /// - The security level of the verified proof is insufficient.
    pub fn verify(&self, batch: &ProvenBatch) -> Result<(), BatchVerifierError> {
        let stack_inputs = BatchKernel::build_input_stack(
            batch.reference_block_commitment(),
            batch.id().as_word(),
        );

        // The skeleton kernel drops its inputs and emits the all-zero output region, so the proof
        // attests to empty outputs. Once the kernel computes the real commitments, these empty
        // values become `batch.input_notes().commitment()`, the batch note tree root and
        // `batch.batch_expiration_block_num()`.
        let stack_outputs =
            BatchKernel::build_output_stack(Word::empty(), Word::empty(), BlockNumber::from(0u32));

        let proof_security_level = verify(
            self.batch_program_info.clone(),
            stack_inputs,
            stack_outputs,
            batch.proof().clone(),
        )
        .map_err(BatchVerifierError::BatchVerificationFailed)?;

        if proof_security_level < self.proof_security_level {
            return Err(BatchVerifierError::InsufficientProofSecurityLevel {
                actual: proof_security_level,
                expected_minimum: self.proof_security_level,
            });
        }

        Ok(())
    }
}
