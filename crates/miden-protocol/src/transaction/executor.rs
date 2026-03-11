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

/// A transaction-scoped program executor used by `miden-tx`.
pub trait TransactionProgramExecutor: Sized {
    /// Execute the provided program against the given host.
    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>>;
}

/// A factory for constructing transaction program executors.
pub trait TransactionProgramExecutorFactory {
    /// The executor type created by this factory.
    type Executor: TransactionProgramExecutor;

    /// Create a new executor configured with the provided transaction inputs and options.
    fn create_executor(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self::Executor;
}

/// Default factory that executes transactions with `FastProcessor`.
pub struct DefaultTransactionProgramExecutorFactory;

impl TransactionProgramExecutor for FastProcessor {
    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        FastProcessor::execute(self, program, host)
    }
}

impl TransactionProgramExecutorFactory for DefaultTransactionProgramExecutorFactory {
    type Executor = FastProcessor;

    fn create_executor(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self::Executor {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
    }
}

#[doc(hidden)]
pub use DefaultTransactionProgramExecutorFactory as DefaultProgramExecutorFactory;
#[doc(hidden)]
pub use TransactionProgramExecutor as ProgramExecutor;
#[doc(hidden)]
pub use TransactionProgramExecutorFactory as ProgramExecutorFactory;
