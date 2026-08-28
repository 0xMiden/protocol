use miden_processor::TraceBuildInputs;
use miden_protocol::block::{BlockOutputs, ProposedBlock};

// EXECUTED BLOCK
// ================================================================================================

/// A [`ProposedBlock`] whose block kernel has been executed, but not yet proven.
///
/// Produced by [`BlockExecutor::execute`](crate::BlockExecutor::execute) and consumed by
/// [`LocalBlockProver::prove`](crate::LocalBlockProver::prove). It carries the executed block's
/// trace inputs so that proving only needs to build the trace and generate the proof.
pub struct ExecutedBlock {
    proposed_block: ProposedBlock,
    trace_inputs: TraceBuildInputs,
    block_outputs: BlockOutputs,
}

impl ExecutedBlock {
    /// Creates a new [`ExecutedBlock`] from the proposed block, the trace inputs and the public
    /// outputs produced by executing the block kernel over it.
    pub(crate) fn new(
        proposed_block: ProposedBlock,
        trace_inputs: TraceBuildInputs,
        block_outputs: BlockOutputs,
    ) -> Self {
        Self {
            proposed_block,
            trace_inputs,
            block_outputs,
        }
    }

    /// Returns the [`ProposedBlock`] this block was executed from.
    pub fn proposed_block(&self) -> &ProposedBlock {
        &self.proposed_block
    }

    /// Returns the public outputs produced by the block kernel.
    pub fn block_outputs(&self) -> &BlockOutputs {
        &self.block_outputs
    }

    /// Consumes the executed block, returning the trace inputs needed to prove it.
    pub(crate) fn into_trace_inputs(self) -> TraceBuildInputs {
        self.trace_inputs
    }
}
