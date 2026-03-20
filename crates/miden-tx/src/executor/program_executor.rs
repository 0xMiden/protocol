use miden_processor::advice::AdviceInputs;
use miden_processor::{
    ExecutionError,
    ExecutionOptions,
    ExecutionOutput,
    FastProcessor,
    FutureMaybeSend,
    Host,
    Program,
    StackInputs,
};

/// A transaction-scoped program executor used by
/// [`TransactionExecutor`](super::TransactionExecutor).
///
/// TODO: Move this trait into `miden-vm` once the executor boundary is
/// consolidated there.
pub trait ProgramExecutor {
    /// Create a new executor configured with the provided transaction inputs and options.
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self
    where
        Self: Sized;

    /// Execute the provided program against the given host.
    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>>;
}

impl ProgramExecutor for FastProcessor {
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
    }

    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        FastProcessor::execute(self, program, host)
    }
}
