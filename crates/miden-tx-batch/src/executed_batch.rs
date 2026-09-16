use miden_processor::{ExecutionWitness, PrecompileWitness};
use miden_protocol::batch::{BatchOutputs, ProposedBatch};

// EXECUTED BATCH
// ================================================================================================

/// A [`ProposedBatch`] whose batch kernel has been executed, but not yet proven.
///
/// Produced by [`BatchExecutor::execute`](crate::BatchExecutor::execute) and consumed by
/// [`LocalBatchProver::prove`](crate::LocalBatchProver::prove). It carries the witnesses proving
/// needs: the batch kernel's execution witness and the merged precompile witness of the batch's
/// transactions.
pub struct ExecutedBatch {
    proposed_batch: ProposedBatch,
    witness: ExecutionWitness,
    precompile_witness: Option<PrecompileWitness>,
    batch_outputs: BatchOutputs,
}

impl ExecutedBatch {
    /// Creates a new [`ExecutedBatch`] from the proposed batch, the execution witness, the merged
    /// precompile witness of its transactions and the public outputs produced by executing the
    /// batch kernel over it.
    pub(crate) fn new(
        proposed_batch: ProposedBatch,
        witness: ExecutionWitness,
        precompile_witness: Option<PrecompileWitness>,
        batch_outputs: BatchOutputs,
    ) -> Self {
        Self {
            proposed_batch,
            witness,
            precompile_witness,
            batch_outputs,
        }
    }

    /// Returns the [`ProposedBatch`] this batch was executed from.
    pub fn proposed_batch(&self) -> &ProposedBatch {
        &self.proposed_batch
    }

    /// Returns the merged precompile witness of the batch's transactions, or `None` if no
    /// transaction in the batch deferred precompile work.
    pub fn precompile_witness(&self) -> Option<&PrecompileWitness> {
        self.precompile_witness.as_ref()
    }

    /// Returns the public outputs produced by the batch kernel.
    pub fn batch_outputs(&self) -> &BatchOutputs {
        &self.batch_outputs
    }

    /// Consumes the executed batch, returning the proposed batch and the witnesses needed to prove
    /// it.
    pub(crate) fn into_parts(self) -> (ProposedBatch, ExecutionWitness, Option<PrecompileWitness>) {
        (self.proposed_batch, self.witness, self.precompile_witness)
    }
}
