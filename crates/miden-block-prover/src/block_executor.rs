use miden_processor::{DefaultHost, ExecutionError, ExecutionOptions, FastProcessor};
use miden_protocol::block::{BlockKernel, BlockOutputs, ProposedBlock};

use crate::{BlockProverError, ExecutedBlock};

// BLOCK EXECUTOR
// ================================================================================================

/// Executes the block kernel over a [`ProposedBlock`], producing an [`ExecutedBlock`].
#[derive(Clone, Default)]
pub struct BlockExecutor;

impl BlockExecutor {
    /// Creates a new [`BlockExecutor`] instance.
    pub fn new() -> Self {
        Self
    }

    /// Runs the block kernel over the [`ProposedBlock`], returning an [`ExecutedBlock`] that can be
    /// passed to [`LocalBlockProver::prove`](crate::LocalBlockProver::prove).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the block kernel program fails to execute;
    /// - the kernel output stack fails to parse.
    pub fn execute(
        &self,
        proposed_block: ProposedBlock,
    ) -> Result<ExecutedBlock, BlockProverError> {
        let (stack_inputs, advice_inputs) = BlockKernel::prepare_inputs(&proposed_block);

        let processor = FastProcessor::new_with_options(
            stack_inputs,
            advice_inputs,
            ExecutionOptions::default(),
        )
        .map_err(ExecutionError::advice_error_no_context)
        .map_err(BlockProverError::BlockKernelExecutionFailed)?;

        let execution_witness = processor
            .execute_for_proving_sync(&BlockKernel::main(), &mut DefaultHost::default())
            .map_err(BlockProverError::BlockKernelExecutionFailed)?;

        // Parse and validate the output stack shape (padding cells are zero); the actual output
        // values themselves are not checked until the kernel computes them.
        let block_outputs = BlockOutputs::parse(execution_witness.claim().stack_outputs())
            .map_err(BlockProverError::BlockKernelOutputInvalid)?;

        Ok(ExecutedBlock::new(proposed_block, execution_witness, block_outputs))
    }
}
