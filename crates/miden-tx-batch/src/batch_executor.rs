use miden_processor::{DefaultHost, ExecutionError, ExecutionOptions, FastProcessor};
use miden_protocol::CoreLibrary;
use miden_protocol::batch::{BatchId, BatchKernel, BatchOutputs, ProposedBatch};
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
    /// When set, fed to the kernel as the public `BATCH_ID` instead of the proposed batch's id.
    batch_id_override: Option<BatchId>,
}

impl BatchExecutor {
    /// Creates a new [`BatchExecutor`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Extends the advice inputs with the provided ones.
    ///
    /// Exposed for testing only: it lets kernel tests override the advice derived from the
    /// proposed batch (e.g. with tampered entries) to drive the kernel's rejection paths.
    #[cfg(any(feature = "testing", test))]
    pub fn extend_advice_inputs(mut self, advice_inputs: AdviceInputs) -> Self {
        self.advice_inputs.extend(advice_inputs);
        self
    }

    /// Overrides the public `BATCH_ID` fed to the kernel.
    ///
    /// Exposed for testing only: together with [`Self::extend_advice_inputs`] it lets kernel
    /// tests anchor the kernel to a forged transaction tuple list that [`ProposedBatch`]
    /// validation would reject (e.g. one containing duplicate transactions).
    #[cfg(any(feature = "testing", test))]
    pub fn with_batch_id(mut self, batch_id: BatchId) -> Self {
        self.batch_id_override = Some(batch_id);
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
        // Apply the testing-only batch id override, if any.
        let stack_inputs = match self.batch_id_override {
            Some(batch_id) => BatchKernel::build_input_stack(
                proposed_batch.reference_block_header().commitment(),
                batch_id,
            ),
            None => stack_inputs,
        };

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
