use miden_processor::ExecutionWitness;
use miden_protocol::block::{BlockOutputs, ProposedBlock};

// EXECUTED BLOCK
// ================================================================================================

/// A [`ProposedBlock`] whose block kernel has been executed, but not yet proven.
///
/// Produced by [`BlockExecutor::execute`](crate::BlockExecutor::execute) and consumed by
/// [`LocalBlockProver::prove`](crate::LocalBlockProver::prove). It carries the executed block's
/// execution witness so that proving only needs to build the trace and generate the proof.
pub struct ExecutedBlock {
    proposed_block: ProposedBlock,
    execution_witness: ExecutionWitness,
    block_outputs: BlockOutputs,
}

impl ExecutedBlock {
    /// Creates a new [`ExecutedBlock`] from the proposed block, the execution witness and the
    /// public outputs produced by executing the block kernel over it.
    pub(crate) fn new(
        proposed_block: ProposedBlock,
        execution_witness: ExecutionWitness,
        block_outputs: BlockOutputs,
    ) -> Self {
        Self {
            proposed_block,
            execution_witness,
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

    /// Consumes the executed block, returning the execution witness needed to prove it.
    pub(crate) fn into_execution_witness(self) -> ExecutionWitness {
        self.execution_witness
    }
}
