use miden_protocol::Word;
use miden_protocol::batch::{BatchKernel, BatchOutputs, ProvenBatch};
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
/// The batch kernel binds only the batch's `INPUT_NOTES_COMMITMENT`. The batch note tree root and
/// expiration are emitted as the empty word and zero, and input notes are not authenticated against
/// the chain MMR. A successful [`verify`](BatchVerifier::verify) therefore attests that the kernel
/// ran over the batch's `[BLOCK_COMMITMENT, BATCH_ID]` inputs and produced
/// `batch.input_notes().commitment()`, but does **not** bind the batch's output notes, account
/// updates, or expiration. This verifier must not be relied on at a trust boundary.
pub struct BatchVerifier {
    batch_program_info: ProgramInfo,
    min_proof_security_level: u32,
}

impl BatchVerifier {
    /// Returns a new [`BatchVerifier`] instantiated with the specified minimum security level.
    pub fn new(min_proof_security_level: u32) -> Self {
        let batch_program_info = BatchKernel::program_info();
        Self {
            batch_program_info,
            min_proof_security_level,
        }
    }

    /// Verifies the provided [`ProvenBatch`]'s execution proof against the batch kernel.
    ///
    /// On success, returns the security level (in bits) of the verified proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Batch proof verification fails.
    /// - The security level of the verified proof is below the configured minimum.
    pub fn verify(&self, batch: &ProvenBatch) -> Result<u32, BatchVerifierError> {
        let stack_inputs =
            BatchKernel::build_input_stack(batch.reference_block_commitment(), batch.id());

        // The kernel binds the batch's INPUT_NOTES_COMMITMENT but not the batch note tree root or
        // expiration, so those are passed as the empty word and zero.
        let stack_outputs = BatchOutputs::new(
            batch.input_notes().commitment(),
            Word::empty(),
            BlockNumber::from(0u32),
        )
        .into_stack_outputs();

        let verified_security_level = verify(
            self.batch_program_info.clone(),
            stack_inputs,
            stack_outputs,
            batch.proof().clone(),
        )
        .map_err(BatchVerifierError::BatchVerificationFailed)?;

        if verified_security_level < self.min_proof_security_level {
            return Err(BatchVerifierError::InsufficientProofSecurityLevel {
                actual: verified_security_level,
                expected_minimum: self.min_proof_security_level,
            });
        }

        Ok(verified_security_level)
    }
}
