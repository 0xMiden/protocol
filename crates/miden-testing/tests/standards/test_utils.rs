use miden_processor::ExecutionOutput;
use miden_protocol::errors::MasmError;
use miden_testing::executor::CodeExecutor;
use miden_testing::{ExecError, assert_execution_error};

// HELPER FUNCTIONS
// ================================================================================================

/// Execute a MASM script with the default host.
pub async fn execute_masm_script(script_code: &str) -> Result<ExecutionOutput, ExecError> {
    CodeExecutor::with_default_host().run(script_code).await
}

/// Helper to assert execution fails with a specific MASM assertion error.
pub async fn assert_execution_fails_with(script_code: &str, expected_error: &MasmError) {
    let result = execute_masm_script(script_code).await;
    assert_execution_error!(result, expected_error);
}
