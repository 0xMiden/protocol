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
/// The batch kernel currently emits and binds only the batch's `INPUT_NOTES_COMMITMENT`; the batch
/// note tree root and expiration are still all-zero placeholders, and input notes are not yet
/// authenticated against the chain MMR. A successful [`verify`](BatchVerifier::verify) therefore
/// attests that the kernel ran over the batch's `[BLOCK_COMMITMENT, BATCH_ID]` inputs and produced
/// `batch.input_notes().commitment()`, but does **not** yet bind the batch's output notes, account
/// updates, or expiration. This verifier must not be relied on at a trust boundary until the
/// remaining kernel verification logic lands.
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
        let stack_inputs =
            BatchKernel::build_input_stack(batch.reference_block_commitment(), batch.id());

        // The kernel emits the batch's INPUT_NOTES_COMMITMENT; the batch note tree root and
        // expiration are still all-zero placeholders (wired up in follow-up work, at which point
        // they become the batch note tree root and `batch.batch_expiration_block_num()`).
        let stack_outputs = BatchOutputs::new(
            batch.input_notes().commitment(),
            Word::empty(),
            BlockNumber::from(0u32),
        )
        .into_stack_outputs();

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
