use miden_processor::{DefaultHost, ExecutionError, ExecutionOptions, FastProcessor};
use miden_protocol::CoreLibrary;
use miden_protocol::batch::{BatchKernel, BatchOutputs, ProposedBatch};
use miden_protocol::errors::ProvenBatchError;
use miden_protocol::vm::{AdviceInputs, StackInputs};

use crate::ExecutedBatch;

// BATCH EXECUTOR
// ================================================================================================

/// Executes the batch kernel over a [`ProposedBatch`], producing an [`ExecutedBatch`].
#[derive(Clone, Default)]
pub struct BatchExecutor;

impl BatchExecutor {
    /// Creates a new [`BatchExecutor`] instance.
    pub fn new() -> Self {
        Self
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
        let (stack_inputs, advice_inputs) = BatchKernel::prepare_inputs(&proposed_batch);
        self.execute_with_inputs(proposed_batch, stack_inputs, advice_inputs)
    }

    /// Runs the batch kernel over the [`ProposedBatch`], merging the provided advice inputs onto
    /// those derived from the batch (overriding matching keys).
    ///
    /// Exposed for testing only: it lets kernel tests override the advice derived from the
    /// proposed batch (e.g. with tampered entries) to drive the kernel's rejection paths.
    #[cfg(any(feature = "testing", test))]
    pub fn execute_with_advice_overrides(
        &self,
        proposed_batch: ProposedBatch,
        override_advice: AdviceInputs,
    ) -> Result<ExecutedBatch, ProvenBatchError> {
        let (stack_inputs, mut advice_inputs) = BatchKernel::prepare_inputs(&proposed_batch);
        advice_inputs.extend(override_advice);
        self.execute_with_inputs(proposed_batch, stack_inputs, advice_inputs)
    }

    /// Runs the batch kernel over the given stack and advice inputs.
    fn execute_with_inputs(
        &self,
        proposed_batch: ProposedBatch,
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
    ) -> Result<ExecutedBatch, ProvenBatchError> {
        let processor = FastProcessor::new_with_options(
            stack_inputs,
            advice_inputs,
            ExecutionOptions::default(),
        )
        .map_err(ExecutionError::advice_error_no_context)
        .map_err(ProvenBatchError::BatchKernelExecutionFailed)?;

        // Load the core library so the host has the `miden::core` procedures and the `sorted_array`
        // event handlers the batch kernel relies on.
        let mut host = DefaultHost::default();
        host.load_library(&CoreLibrary::default())
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
