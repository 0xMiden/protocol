use alloc::boxed::Box;
use alloc::vec::Vec;

use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOptions,
    FastProcessor,
    PrecompileWitness,
};
use miden_protocol::batch::{BatchKernel, BatchOutputs, ProposedBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::errors::ProvenBatchError;
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{CoreLibrary, Word};

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
    /// The executed batch carries the ordered precompile witnesses of the batch's transactions,
    /// which the prover settles with a single precompile proof.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the batch contains more transactions than the kernel supports, or a feature the kernel
    ///   does not yet support (an input note authenticated within the batch, or a pre-erasure note
    ///   union exceeding the kernel's fixed-size regions);
    /// - the batch kernel program fails to execute or defers precompile work of its own;
    /// - the kernel output stack fails to parse;
    /// - the kernel outputs do not match the outputs expected for the proposed batch.
    pub fn execute(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ExecutedBatch, ProvenBatchError> {
        self.execute_with(proposed_batch, AdviceInputs::default())
    }

    /// Runs the batch kernel with additional advice inputs merged onto those derived from the
    /// proposed batch, overriding matching advice-map keys.
    ///
    /// This exists so tests can forge the data the kernel unhashes and assert that it aborts.
    /// Production callers must use [`BatchExecutor::execute`], which derives every advice input
    /// from the proposed batch itself.
    ///
    /// # Errors
    ///
    /// Same as [`BatchExecutor::execute`].
    #[cfg(feature = "testing")]
    pub fn execute_with_advice(
        &self,
        proposed_batch: ProposedBatch,
        advice_inputs: AdviceInputs,
    ) -> Result<ExecutedBatch, ProvenBatchError> {
        self.execute_with(proposed_batch, advice_inputs)
    }

    fn execute_with(
        &self,
        proposed_batch: ProposedBatch,
        advice_inputs: AdviceInputs,
    ) -> Result<ExecutedBatch, ProvenBatchError> {
        BatchKernel::ensure_supported(&proposed_batch)?;

        let precompile_witnesses = Self::collect_precompile_witnesses(&proposed_batch);

        let (stack_inputs, mut batch_advice_inputs) = BatchKernel::prepare_inputs(&proposed_batch);
        batch_advice_inputs.extend(advice_inputs);

        let processor = FastProcessor::new_with_options(
            stack_inputs,
            batch_advice_inputs,
            self.execution_options,
        )
        .map_err(ExecutionError::advice_error_no_context)
        .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        // Load the core library so the host has the `miden::core` procedures and the `sorted_array`
        // event handlers the batch kernel relies on.
        let mut host = DefaultHost::default();
        host.load_library(&CoreLibrary::default())
            .expect("loading the core library into the host should succeed");

        let witness = processor
            .execute_for_proving_sync(&BatchKernel::main(), &mut host)
            .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        let (witness, precompile_witness) = witness.into_parts();

        // Executing the batch kernel must never require precompiles of its own.
        if precompile_witness.is_some() {
            return Err(ProvenBatchError::BatchProofContainsPrecompiles);
        }

        // Parse and validate the output stack shape (zero padding, u32 expiration).
        let batch_outputs = BatchOutputs::parse(witness.claim().stack_outputs())
            .map_err(ProvenBatchError::BatchKernelOutputInvalid)?;

        // Reject if the kernel's outputs do not match the proposed batch, so drift is caught early.
        let expected_outputs = BatchOutputs::new(
            proposed_batch.input_notes().commitment(),
            Word::empty(),
            BlockNumber::from(0u32),
        );
        if batch_outputs != expected_outputs {
            return Err(ProvenBatchError::BatchKernelOutputMismatch {
                expected: Box::new(expected_outputs),
                actual: Box::new(batch_outputs),
            });
        }

        Ok(ExecutedBatch::new(proposed_batch, witness, precompile_witnesses, batch_outputs))
    }

    /// Collects the outstanding precompile witnesses in transaction order.
    ///
    /// Their order and duplicates are significant to the aggregate precompile statement.
    fn collect_precompile_witnesses(proposed_batch: &ProposedBatch) -> Vec<PrecompileWitness> {
        proposed_batch
            .transactions()
            .iter()
            .filter_map(|transaction| transaction.precompile_witness().cloned())
            .collect()
    }
}

impl Default for BatchExecutor {
    fn default() -> Self {
        Self::new()
    }
}
