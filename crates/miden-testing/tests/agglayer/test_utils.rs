extern crate alloc;

use alloc::sync::Arc;

use miden_agglayer::agglayer_library;
pub use miden_agglayer::testing::{
    ClaimDataSource,
    LEAF_VALUE_VECTORS_JSON,
    LeafValueVector,
    MerkleProofVerificationFile,
    MtfVectorsFile,
    SOLIDITY_CANONICAL_ZEROS,
    SOLIDITY_MERKLE_PROOF_VECTORS,
};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_processor::advice::AdviceInputs;
use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOutput,
    FastProcessor,
    Program,
    StackInputs,
};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::sync::LazyLock;

// EMBEDDED TEST VECTOR JSON FILES
// ================================================================================================

/// Merkle Tree Frontier (MTF) vectors JSON from the Foundry-generated file.
pub const MTF_VECTORS_JSON: &str = include_str!(
    "../../../miden-agglayer/solidity-compat/test-vectors/merkle_tree_frontier_vectors.json"
);

// LAZY-PARSED TEST VECTORS
// ================================================================================================

/// Lazily parsed Merkle Tree frontier (MTF) vectors from the JSON file.
pub static SOLIDITY_MTF_VECTORS: LazyLock<MtfVectorsFile> = LazyLock::new(|| {
    serde_json::from_str(MTF_VECTORS_JSON).expect("failed to parse MTF vectors JSON")
});

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

    let stack_inputs = StackInputs::new(&[]).unwrap();
    let advice_inputs = advice_inputs.unwrap_or_default();

    let processor =
        FastProcessor::new(stack_inputs).with_advice(advice_inputs).with_debugging(true);
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
