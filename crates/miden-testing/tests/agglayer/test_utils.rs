extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;

use miden_agglayer::agglayer_library;
// Re-export shared test vector types and constants from miden_agglayer::testing.
pub use miden_agglayer::testing::{
    ClaimDataSource,
    LEAF_VALUE_VECTORS_JSON,
    LeafValueVector,
    MerkleProofVerificationFile,
    SOLIDITY_CANONICAL_ZEROS,
    SOLIDITY_MERKLE_PROOF_VECTORS,
    SOLIDITY_MMR_FRONTIER_VECTORS,
};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_processor::fast::{ExecutionOutput, FastProcessor};
use miden_processor::{AdviceInputs, DefaultHost, ExecutionError, Program, StackInputs};
use miden_protocol::transaction::TransactionKernel;

// HELPER FUNCTIONS
// ================================================================================================

/// Execute a program with a default host and optional advice inputs.
pub async fn execute_program_with_default_host(
    program: Program,
    advice_inputs: Option<AdviceInputs>,
) -> Result<ExecutionOutput, ExecutionError> {
    let mut host = DefaultHost::default();

    let test_lib = TransactionKernel::library();
    host.load_library(test_lib.mast_forest()).unwrap();

    let std_lib = CoreLibrary::default();
    host.load_library(std_lib.mast_forest()).unwrap();

    for (event_name, handler) in std_lib.handlers() {
        host.register_handler(event_name, handler)?;
    }

    let agglayer_lib = agglayer_library();
    host.load_library(agglayer_lib.mast_forest()).unwrap();

    let stack_inputs = StackInputs::new(vec![]).unwrap();
    let advice_inputs = advice_inputs.unwrap_or_default();

    let processor = FastProcessor::new_debug(stack_inputs.as_slice(), advice_inputs);
    processor.execute(&program, &mut host).await
}

/// Execute a MASM script with the default host
pub async fn execute_masm_script(script_code: &str) -> Result<ExecutionOutput, ExecutionError> {
    let agglayer_lib = agglayer_library();

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib)
        .unwrap()
        .assemble_program(script_code)
        .unwrap();

    execute_program_with_default_host(program, None).await
}

/// Helper to assert execution fails with a specific error message
pub async fn assert_execution_fails_with(script_code: &str, expected_error: &str) {
    let result = execute_masm_script(script_code).await;
    assert!(result.is_err(), "Expected execution to fail but it succeeded");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains(expected_error),
        "Expected error containing '{}', got: {}",
        expected_error,
        error_msg
    );
}
