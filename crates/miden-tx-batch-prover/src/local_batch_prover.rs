use alloc::boxed::Box;

use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::errors::ProvenBatchError;
use miden_tx::TransactionVerifier;

// LOCAL BATCH PROVER
// ================================================================================================

/// A local prover for transaction batches, proving the transactions in a [`ProposedBatch`] and
/// returning a [`ProvenBatch`].
#[derive(Clone)]
pub struct LocalBatchProver {
    proof_security_level: u32,
}

impl LocalBatchProver {
    /// Creates a new [`LocalBatchProver`] instance.
    pub fn new(proof_security_level: u32) -> Self {
        Self { proof_security_level }
    }

    /// Attempts to prove the [`ProposedBatch`] into a [`ProvenBatch`].
    ///
    /// Currently we don't perform any recursive proving. For now, this function runs a native
    /// verifier for each transaction separately, and outputs a `ProvenBatch` object if all of the
    /// individual proofs verify.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a proof of any transaction in the batch fails to verify.
    pub fn prove(&self, proposed_batch: ProposedBatch) -> Result<ProvenBatch, ProvenBatchError> {
        let verifier = TransactionVerifier::new(self.proof_security_level);

        for tx in proposed_batch.transactions() {
            verifier.verify(tx).map_err(|source| {
                ProvenBatchError::TransactionVerificationFailed {
                    transaction_id: tx.id(),
                    source: Box::new(source),
                }
            })?;
        }

        self.prove_inner(proposed_batch)
    }

    /// Proves the provided [`ProposedBatch`] into a [`ProvenBatch`], **without verifying batches
    /// and proving the block**.
    ///
    /// This is exposed for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn prove_dummy(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ProvenBatch, ProvenBatchError> {
        self.prove_inner(proposed_batch)
    }

    /// Converts a proposed batch into a proven batch.
    ///
    /// For now, this doesn't do anything interesting.
    fn prove_inner(&self, proposed_batch: ProposedBatch) -> Result<ProvenBatch, ProvenBatchError> {
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

        ProvenBatch::new(
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
