use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_prover::{ExecutionProof, Prover};

use crate::{BatchProverError, ExecutedBatch};

// LOCAL BATCH PROVER
// ================================================================================================

/// A local prover for transaction batches.
///
/// Proves an [`ExecutedBatch`] (produced by [`BatchExecutor`](crate::BatchExecutor)) into a
/// [`ProvenBatch`] carrying an [`ExecutionProof`] over the batch's public commitments.
#[derive(Clone, Default)]
pub struct LocalBatchProver {
    prover: Prover,
}

impl LocalBatchProver {
    /// Creates a new [`LocalBatchProver`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Proves the [`ExecutedBatch`] into a [`ProvenBatch`].
    ///
    /// Builds the execution trace from the executed batch and generates the proof, attaching it to
    /// the returned [`ProvenBatch`]. The kernel's public outputs are not yet cross-checked against
    /// the proposed batch's expected values.
    ///
    /// # Errors
    ///
    /// Returns an error if proof generation fails or the proven batch cannot be built.
    pub fn prove(&self, executed_batch: ExecutedBatch) -> Result<ProvenBatch, BatchProverError> {
        let (proposed_batch, execution_witness) = executed_batch.into_parts();

        let proof = self
            .prover
            .prove_full(execution_witness)
            .map_err(BatchProverError::ProofGenerationFailed)?;

        Self::build_proven_batch(proposed_batch, proof)
    }

    /// Returns a [`ProvenBatch`] built from the proposed batch with a dummy [`ExecutionProof`]
    /// attached, without running the batch kernel.
    #[cfg(any(feature = "testing", test))]
    pub fn prove_dummy(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, BatchProverError> {
        let proof = miden_protocol::testing::proof::dummy_execution_proof();
        Self::build_proven_batch(proposed_batch, proof)
    }

    /// Combines the parts of a [`ProposedBatch`] with the produced [`ExecutionProof`] into a
    /// [`ProvenBatch`].
    fn build_proven_batch(
        proposed_batch: ProposedBatch,
        proof: ExecutionProof,
    ) -> Result<ProvenBatch, BatchProverError> {
        let tx_headers = proposed_batch.transaction_headers();
        let (
            _transactions,
            block_header,
            _block_chain,
            _authenticatable_unauthenticated_notes,
            id,
            updated_accounts,
            input_notes,
            output_notes,
            batch_expiration_block_num,
        ) = proposed_batch.into_parts();

        ProvenBatch::new_unchecked(
            id,
            block_header.commitment(),
            block_header.block_num(),
            updated_accounts,
            input_notes,
            output_notes,
            batch_expiration_block_num,
            tx_headers,
            proof,
        )
        .map_err(BatchProverError::ProvenBatchBuildFailed)
    }
}
