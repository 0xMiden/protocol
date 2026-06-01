use miden_processor::{DefaultHost, ExecutionError, ExecutionOptions, FastProcessor};
use miden_protocol::CoreLibrary;
use miden_protocol::batch::{BatchKernel, BatchOutputs, ProposedBatch};
use miden_protocol::errors::ProvenBatchError;
use miden_protocol::vm::AdviceInputs;

use crate::ExecutedBatch;

// BATCH EXECUTOR
// ================================================================================================

/// Executes the batch kernel over a [`ProposedBatch`], producing an [`ExecutedBatch`].
#[derive(Clone, Default)]
pub struct BatchExecutor {
    /// Extra advice inputs merged onto those derived from the proposed batch before execution.
    advice_inputs: AdviceInputs,
}

impl BatchExecutor {
    /// Creates a new [`BatchExecutor`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Extends the advice inputs merged onto those derived from the proposed batch before
    /// execution. Entries provided here override matching keys from the derived advice.
    ///
    /// This is primarily a testing hook for exercising the batch kernel's rejection paths by
    /// injecting tampered advice, mirroring
    /// [`TransactionContextBuilder::extend_advice_inputs`](https://docs.rs/miden-testing).
    pub fn extend_advice_inputs(mut self, advice_inputs: AdviceInputs) -> Self {
        self.advice_inputs.extend(advice_inputs);
        self
    }

    /// Runs the batch kernel over the [`ProposedBatch`], returning an [`ExecutedBatch`] that can be
    /// passed to [`LocalBatchProver::prove`](crate::LocalBatchProver::prove).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the batch kernel program fails to execute;
    /// - the kernel output stack fails to parse.
    pub fn execute(
        &self,
        proposed_batch: ProposedBatch,
    ) -> Result<ExecutedBatch, ProvenBatchError> {
        let (stack_inputs, mut advice_inputs) = BatchKernel::prepare_inputs(&proposed_batch);
        // Merge any caller-provided advice, overriding matching keys from the derived advice.
        advice_inputs.extend(self.advice_inputs.clone());

        let processor = FastProcessor::new_with_options(
            stack_inputs,
            advice_inputs,
            ExecutionOptions::default(),
        )
        .map_err(ExecutionError::advice_error_no_context)
        .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        // The batch kernel calls `miden::core` procedures (poseidon2, mem, ...), so the core
        // library must be available to the host at runtime.
        let mut host = DefaultHost::default();
        host.load_library(CoreLibrary::default().mast_forest())
            .expect("loading the core library into the host should succeed");

        let trace_inputs = processor
            .execute_trace_inputs_sync(&BatchKernel::main(), &mut host)
            .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        // Parse and validate the output stack shape (padding cells are zero and the expiration
        // fits in u32); the actual output values themselves are not checked until the kernel
        // verifies them.
        let batch_outputs = BatchOutputs::parse(trace_inputs.stack_outputs())
            .map_err(ProvenBatchError::BatchKernelOutputInvalid)?;

        Ok(ExecutedBatch::new(proposed_batch, trace_inputs, batch_outputs))
    }
}
