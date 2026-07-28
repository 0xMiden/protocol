extern crate alloc;

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager, Linkage};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOutput,
    FastProcessor,
    Program,
    StackInputs,
};
use miden_protocol::ProtocolLib;
use miden_protocol::errors::MasmError;
use miden_standards::StandardsLib;

// HELPER FUNCTIONS
// ================================================================================================

/// Execute a program with a default host loading the core, protocol, and standards libraries.
pub async fn execute_program_with_default_host(
    program: Program,
) -> Result<ExecutionOutput, ExecutionError> {
    let mut host = DefaultHost::default();

    let std_lib = CoreLibrary::default();
    host.load_library(std_lib.mast_forest()).unwrap();

    for (event_name, handler) in std_lib.handlers() {
        host.register_handler(event_name, handler)?;
    }

    let protocol_lib = ProtocolLib::default();
    host.load_library(protocol_lib.mast_forest()).unwrap();

    let standards_lib = StandardsLib::default();
    host.load_library(standards_lib.mast_forest()).unwrap();

    let stack_inputs = StackInputs::new(&[]).unwrap();

    let processor = FastProcessor::new(stack_inputs);
    processor.execute(&program, &mut host).await
}

/// Execute a MASM script with the default host.
pub async fn execute_masm_script(script_code: &str) -> Result<ExecutionOutput, ExecutionError> {
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_package(CoreLibrary::default().package(), Linkage::Dynamic)
        .unwrap()
        .with_package(StandardsLib::default().package(), Linkage::Dynamic)
        .unwrap()
        .assemble_program("standards-test-script", script_code)
        .unwrap()
        .try_into_program()
        .unwrap();

    execute_program_with_default_host(program).await
}

/// Helper to assert execution fails with a specific MASM assertion error.
pub async fn assert_execution_fails_with(script_code: &str, expected_error: &MasmError) {
    let result = execute_masm_script(script_code).await;
    assert!(result.is_err(), "Expected execution to fail but it succeeded");

    let error = result.unwrap_err();
    assert!(
        expected_error.matches_execution_error(&error),
        "Expected error {}, got: {}",
        expected_error,
        error
    );
}
