#[cfg(test)]
use miden_processor::DefaultHost;
use miden_processor::fast::{ExecutionOutput, FastProcessor};
use miden_processor::{AdviceInputs, AsyncHost, Program, StackInputs};
#[cfg(test)]
use miden_protocol::assembly::Assembler;

use crate::ExecError;

// CODE EXECUTOR
// ================================================================================================

/// Helper for executing arbitrary code within arbitrary hosts.
pub(crate) struct CodeExecutor<H> {
    host: H,
    stack_inputs: Option<StackInputs>,
    advice_inputs: AdviceInputs,
}

impl<H: AsyncHost> CodeExecutor<H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    pub(crate) fn new(host: H) -> Self {
        Self {
            host,
            stack_inputs: None,
            advice_inputs: AdviceInputs::default(),
        }
    }

    pub fn extend_advice_inputs(mut self, advice_inputs: AdviceInputs) -> Self {
        self.advice_inputs.extend(advice_inputs);
        self
    }

    pub fn stack_inputs(mut self, stack_inputs: StackInputs) -> Self {
        self.stack_inputs = Some(stack_inputs);
        self
    }

    /// Compiles and runs the desired code in the host and returns the [`Process`] state.
    #[cfg(test)]
    pub async fn run(self, code: &str) -> Result<ExecutionOutput, ExecError> {
        use alloc::borrow::ToOwned;
        use alloc::sync::Arc;

        use miden_protocol::assembly::debuginfo::{SourceLanguage, Uri};
        use miden_protocol::assembly::{DefaultSourceManager, SourceManagerSync};
        use miden_standards::code_builder::CodeBuilder;

        let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
        let assembler: Assembler = CodeBuilder::with_kernel_library(source_manager.clone()).into();

        // Virtual file name should be unique.
        let virtual_source_file =
            source_manager.load(SourceLanguage::Masm, Uri::new("_user_code"), code.to_owned());
        let program = assembler.assemble_program(virtual_source_file).unwrap();

        self.execute_program(program).await
    }

    /// Executes the provided [`Program`] and returns the [`Process`] state.
    ///
    /// To improve the error message quality, convert the returned [`ExecutionError`] into a
    /// [`Report`](miden_protocol::assembly::diagnostics::Report).
    pub async fn execute_program(mut self, program: Program) -> Result<ExecutionOutput, ExecError> {
        // This reverses the stack inputs (even though it doesn't look like it does) because the
        // fast processor expects the reverse order.
        //
        // Once we use the FastProcessor for execution and proving, we can change the way these
        // inputs are constructed in TransactionKernel::prepare_inputs.
        let stack_inputs =
            StackInputs::new(self.stack_inputs.unwrap_or_default().iter().copied().collect())
                .unwrap();

        let processor = FastProcessor::new_debug(stack_inputs.as_slice(), self.advice_inputs);

        let execution_output =
            processor.execute(&program, &mut self.host).await.map_err(ExecError::new)?;

        Ok(execution_output)
    }
}

#[cfg(test)]
impl CodeExecutor<DefaultHost> {
    pub fn with_default_host() -> Self {
        use miden_core_lib::CoreLibrary;
        use miden_protocol::ProtocolLib;
        use miden_protocol::transaction::TransactionKernel;
        use miden_standards::StandardsLib;

        let mut host = DefaultHost::default();

        let core_lib = CoreLibrary::default();
        host.load_library(core_lib.mast_forest()).unwrap();

        let standards_lib = StandardsLib::default();
        host.load_library(standards_lib.mast_forest()).unwrap();

        let protocol_lib = ProtocolLib::default();
        host.load_library(protocol_lib.mast_forest()).unwrap();

        let kernel_lib = TransactionKernel::library();
        host.load_library(kernel_lib.mast_forest()).unwrap();

        CodeExecutor::new(host)
    }
}
