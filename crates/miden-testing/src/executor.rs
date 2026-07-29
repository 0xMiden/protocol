use alloc::boxed::Box;

use miden_processor::advice::AdviceInputs;
use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOptions,
    ExecutionOutput,
    FastProcessor,
    Host,
    Program,
    StackInputs,
};
use miden_protocol::assembly::Assembler;
use miden_protocol::vm::{DebugSourceNodeId, Package, PackageDebugInfo};

use crate::ExecError;

// CODE EXECUTOR
// ================================================================================================

/// Helper for executing arbitrary code within arbitrary hosts.
pub struct CodeExecutor<H> {
    host: H,
    stack_inputs: Option<StackInputs>,
    advice_inputs: AdviceInputs,
    execution_options: Option<ExecutionOptions>,
}

impl<H: Host> CodeExecutor<H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    pub(crate) fn new(host: H) -> Self {
        Self {
            host,
            stack_inputs: None,
            advice_inputs: AdviceInputs::default(),
            execution_options: None,
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

    /// Overrides the [`ExecutionOptions`] used to run the program (e.g. to cap `max_cycles`).
    pub fn execution_options(mut self, options: ExecutionOptions) -> Self {
        self.execution_options = Some(options);
        self
    }

    /// Compiles and runs the desired code in the host and returns the [`Process`] state.
    pub async fn run(self, code: &str) -> Result<ExecutionOutput, ExecError> {
        use alloc::borrow::ToOwned;
        use alloc::sync::Arc;

        use miden_protocol::assembly::debuginfo::{SourceLanguage, Uri};
        use miden_protocol::assembly::{DefaultSourceManager, SourceManagerSync};
        use miden_standards::code_builder::CodeBuilder;

        let source_manager: Arc<dyn SourceManagerSync> = Arc::new(DefaultSourceManager::default());
        let assembler: Assembler =
            CodeBuilder::with_kernel_core_package(source_manager.clone()).into();

        // Virtual file name should be unique.
        let virtual_source_file =
            source_manager.load(SourceLanguage::Masm, Uri::new("_user_code"), code.to_owned());
        let package = assembler.assemble_program("mock-tx-code", virtual_source_file).unwrap();

        self.execute_package(package).await
    }

    /// Executes the provided executable [`Package`] and returns the [`Process`] state.
    ///
    /// Package-owned debug information is used when present.
    pub async fn execute_package(
        self,
        package: impl Into<Box<Package>>,
    ) -> Result<ExecutionOutput, ExecError> {
        let package = package.into();
        let package_debug_info = package.debug_info().ok().flatten();
        let entrypoint_source_node = package.entrypoint_source_node();
        let program = package.try_into_program().expect("package should be executable");

        self.execute_program_with_package_debug_info(
            program,
            package_debug_info,
            entrypoint_source_node,
        )
        .await
    }

    async fn execute_program_with_package_debug_info(
        mut self,
        program: Program,
        package_debug_info: Option<PackageDebugInfo>,
        entrypoint_source_node: Option<DebugSourceNodeId>,
    ) -> Result<ExecutionOutput, ExecError> {
        let stack_inputs = self.stack_inputs.unwrap_or_default();

        let processor = FastProcessor::new(stack_inputs)
            .with_advice(self.advice_inputs)
            .map_err(ExecutionError::advice_error_no_context)
            .map_err(ExecError::new)?
            .with_options(self.execution_options.unwrap_or_default())
            .map_err(ExecutionError::advice_error_no_context)
            .map_err(ExecError::new)?;

        let execution_output = match package_debug_info {
            Some(package_debug_info) => match entrypoint_source_node {
                Some(entrypoint_source_node) => {
                    processor
                        .execute_with_package_debug_info_at_source_node(
                            &program,
                            &package_debug_info,
                            entrypoint_source_node,
                            &mut self.host,
                        )
                        .await
                },
                None => {
                    processor
                        .execute_with_package_debug_info(
                            &program,
                            &package_debug_info,
                            &mut self.host,
                        )
                        .await
                },
            },
            None => processor.execute(&program, &mut self.host).await,
        }
        .map_err(ExecError::new)?;

        Ok(execution_output)
    }
}

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

        let kernel_core_package = TransactionKernel::core_package();
        host.load_library(kernel_core_package.mast_forest()).unwrap();

        CodeExecutor::new(host)
    }
}
