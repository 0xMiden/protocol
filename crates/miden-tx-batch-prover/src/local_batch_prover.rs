use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::errors::ProvenBatchError;

// LOCAL BATCH PROVER
// ================================================================================================

/// A local prover for transaction batches, proving the transactions in a [`ProposedBatch`] and
/// returning a [`ProvenBatch`].
#[derive(Clone, Default)]
pub struct LocalBatchProver;

impl LocalBatchProver {
    /// Creates a new [`LocalBatchProver`] instance.
    pub fn new() -> Self {
        Self
    }

    /// Converts the provided [`ProposedBatch`] into a [`ProvenBatch`].
    ///
    /// The batch's transactions are verified when the [`ProposedBatch`] is constructed, so this
    /// currently only repackages the batch. Recursive proving is not yet implemented.
    pub fn prove(&self, proposed_batch: ProposedBatch) -> Result<ProvenBatch, ProvenBatchError> {
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
        )
    }
}
