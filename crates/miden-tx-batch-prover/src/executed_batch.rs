use miden_processor::{StackOutputs, TraceBuildInputs};
use miden_protocol::batch::ProposedBatch;

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
}

impl ExecutedBatch {
    /// Creates a new [`ExecutedBatch`] from the proposed batch and the trace inputs produced by
    /// executing the batch kernel over it.
    pub(crate) fn new(proposed_batch: ProposedBatch, trace_inputs: TraceBuildInputs) -> Self {
        Self { proposed_batch, trace_inputs }
    }

    /// Returns the [`ProposedBatch`] this batch was executed from.
    pub fn proposed_batch(&self) -> &ProposedBatch {
        &self.proposed_batch
    }

    /// Returns the public outputs the batch kernel left on the stack.
    pub fn stack_outputs(&self) -> &StackOutputs {
        self.trace_inputs.stack_outputs()
    }

    /// Consumes the executed batch, returning the proposed batch and the trace inputs needed to
    /// prove it.
    pub(crate) fn into_parts(self) -> (ProposedBatch, TraceBuildInputs) {
        (self.proposed_batch, self.trace_inputs)
    }
}
