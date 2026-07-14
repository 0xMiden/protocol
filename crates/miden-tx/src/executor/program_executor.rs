use miden_processor::advice::AdviceInputs;
use miden_processor::{
    ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, FutureMaybeSend, Host,
    Program, StackInputs,
};
use miden_protocol::vm::{DebugSourceNodeId, PackageDebugInfo};

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

    /// Execute the provided program with package-owned source/debug context.
    ///
    /// Executors that do not support package debug execution may fall back to plain execution.
    fn execute_with_package_debug_info<H: Host + Send>(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node: Option<DebugSourceNodeId>,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>>
    where
        Self: Sized,
    {
        let _ = package_debug_info;
        let _ = entrypoint_source_node;
        self.execute(program, host)
    }
}

impl ProgramExecutor for FastProcessor {
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
            .expect("constructing FastProcessor failed due to invalid advice inputs")
    }

    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        FastProcessor::execute(self, program, host)
    }

    fn execute_with_package_debug_info<H: Host + Send>(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node: Option<DebugSourceNodeId>,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        async move {
            match entrypoint_source_node {
                Some(entrypoint_source_node) => {
                    FastProcessor::execute_with_package_debug_info_at_source_node(
                        self,
                        program,
                        package_debug_info,
                        entrypoint_source_node,
                        host,
                    )
                    .await
                },
                None => {
                    FastProcessor::execute_with_package_debug_info(
                        self,
                        program,
                        package_debug_info,
                        host,
                    )
                    .await
                },
            }
        }
    }
}
