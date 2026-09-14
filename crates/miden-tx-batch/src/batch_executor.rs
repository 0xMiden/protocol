use alloc::vec::Vec;

use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOptions,
    FastProcessor,
    PrecompileWitness,
};
use miden_protocol::batch::{BatchKernel, BatchOutputs, ProposedBatch};
use miden_protocol::errors::ProvenBatchError;

use crate::ExecutedBatch;

// BATCH EXECUTOR
// ================================================================================================

/// Executes the batch kernel over a [`ProposedBatch`], producing an [`ExecutedBatch`].
#[derive(Debug, Clone)]
pub struct BatchExecutor {
    execution_options: ExecutionOptions,
}

impl BatchExecutor {
    /// Creates a new [`BatchExecutor`] instance.
    pub fn new() -> Self {
        Self {
            execution_options: ExecutionOptions::default(),
        }
    }

    /// Sets the [`ExecutionOptions`] used while executing and returns the resulting executor.
    ///
    /// This will overwrite any previously set options.
    #[must_use]
    pub fn with_execution_options(mut self, execution_options: ExecutionOptions) -> Self {
        self.execution_options = execution_options;
        self
    }

    /// Returns the [`ExecutionOptions`] this executor uses.
    pub fn execution_options(&self) -> ExecutionOptions {
        self.execution_options
    }

    /// Runs the batch kernel over the [`ProposedBatch`], returning an [`ExecutedBatch`] that can be
    /// passed to [`LocalBatchProver::prove`](crate::LocalBatchProver::prove).
    ///
    /// The executed batch carries the merged precompile witness of the batch's transactions, which
    /// the prover settles with a single precompile proof.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - more transactions carry outstanding precompile claims than one precompile proof covers;
    /// - a transaction's deferred precompile witness is invalid or cannot be merged;
    /// - the batch kernel program fails to execute or defers precompile work of its own;
    /// - the kernel output stack fails to parse.
    pub fn execute(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ExecutedBatch, ProvenBatchError> {
        let precompile_witness = Self::merge_precompile_witnesses(&proposed_batch)?;

        let (stack_inputs, advice_inputs) = BatchKernel::prepare_inputs(&proposed_batch);

        let processor =
            FastProcessor::new_with_options(stack_inputs, advice_inputs, self.execution_options)
                .map_err(ExecutionError::advice_error_no_context)
                .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        let witness = processor
            .execute_for_proving_sync(&BatchKernel::main(), &mut DefaultHost::default())
            .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        // Executing the batch kernel must never require precompiles of its own.
        if witness.has_precompiles() {
            return Err(ProvenBatchError::BatchProofContainsPrecompiles);
        }

        // Parse and validate the output stack shape (padding cells are zero and the expiration
        // fits in u32); the actual output values themselves are not checked until the kernel
        // verifies them.
        let batch_outputs = BatchOutputs::parse(witness.claim().stack_outputs())
            .map_err(ProvenBatchError::BatchKernelOutputInvalid)?;

        Ok(ExecutedBatch::new(proposed_batch, witness, precompile_witness, batch_outputs))
    }

    /// Merges the outstanding precompile witnesses of the batch's transactions into a single
    /// witness, or returns `None` if no transaction deferred precompile work.
    ///
    /// The witnesses are merged in transaction order, because their order and duplicates among them
    /// are significant to the aggregate precompile statement.
    fn merge_precompile_witnesses(
        proposed_batch: &ProposedBatch,
    ) -> Result<Option<PrecompileWitness>, ProvenBatchError> {
        let witnesses = proposed_batch
            .transactions()
            .iter()
            .filter_map(|transaction| {
                transaction
                    .precompile_witness()
                    .map_err(|source| ProvenBatchError::TransactionPrecompileWitnessInvalid {
                        transaction_id: transaction.id(),
                        source,
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;

        if witnesses.is_empty() {
            return Ok(None);
        }

        PrecompileWitness::merge(witnesses)
            .map(Some)
            .map_err(ProvenBatchError::PrecompileWitnessMergeFailed)
    }
}

impl Default for BatchExecutor {
    fn default() -> Self {
        Self::new()
    }
}
