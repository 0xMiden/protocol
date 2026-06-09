use miden_processor::TraceBuildInputs;
use miden_protocol::batch::{BatchOutputs, ProposedBatch};

// EXECUTED BATCH
// ================================================================================================

/// A [`ProposedBatch`] whose batch kernel has been executed, but not yet proven.
///
/// Produced by [`BatchExecutor::execute`](crate::BatchExecutor::execute) and consumed by
/// [`LocalBatchProver::prove`](crate::LocalBatchProver::prove). It carries the executed batch's
/// trace inputs so that proving only needs to build the trace and generate the proof.
pub struct ExecutedBatch {
    proposed_batch: ProposedBatch,
    trace_inputs: TraceBuildInputs,
    batch_outputs: BatchOutputs,
}

impl ExecutedBatch {
    /// Creates a new [`ExecutedBatch`] from the proposed batch, the trace inputs and the public
    /// outputs produced by executing the batch kernel over it.
    pub(crate) fn new(
        proposed_batch: ProposedBatch,
        trace_inputs: TraceBuildInputs,
        batch_outputs: BatchOutputs,
    ) -> Self {
        Self {
            proposed_batch,
            trace_inputs,
            batch_outputs,
        }
    }

    /// Returns the [`ProposedBatch`] this batch was executed from.
    pub fn proposed_batch(&self) -> &ProposedBatch {
        &self.proposed_batch
    }

    /// Returns the public outputs produced by the batch kernel.
    pub fn batch_outputs(&self) -> &BatchOutputs {
        &self.batch_outputs
    }

    /// Consumes the executed batch, returning the proposed batch and the trace inputs needed to
    /// prove it.
    pub(crate) fn into_parts(self) -> (ProposedBatch, TraceBuildInputs) {
        (self.proposed_batch, self.trace_inputs)
    }
}
