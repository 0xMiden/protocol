extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use miden_agglayer::agglayer_library;
use miden_core_lib::CoreLibrary;
use miden_processor::fast::{ExecutionOutput, FastProcessor};
use miden_processor::{AdviceInputs, DefaultHost, ExecutionError, Program, StackInputs};
use miden_protocol::transaction::TransactionKernel;

/// Execute a program with default host and optional advice inputs
pub async fn execute_program_with_default_host(
    program: Program,
    advice_inputs: Option<AdviceInputs>,
) -> Result<ExecutionOutput, ExecutionError> {
    let mut host = DefaultHost::default();

    let test_lib = TransactionKernel::library();
    host.load_library(test_lib.mast_forest()).unwrap();

    let std_lib = CoreLibrary::default();
    host.load_library(std_lib.mast_forest()).unwrap();

    // Register handlers from std_lib
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

// TESTING HELPERS
// ================================================================================================

/// Type alias for the complex return type of claim_note_test_inputs.
///
/// Contains native types for the new ClaimNoteParams structure:
/// - smt_proof_local_exit_root: `Vec<[u8; 32]>` (256 bytes32 values)
/// - smt_proof_rollup_exit_root: `Vec<[u8; 32]>` (256 bytes32 values)
/// - global_index: [u32; 8]
/// - mainnet_exit_root: [u8; 32]
/// - rollup_exit_root: [u8; 32]
/// - origin_network: u32
/// - origin_token_address: [u8; 20]
/// - destination_network: u32
/// - metadata: [u32; 8]
pub type ClaimNoteTestInputs = (
    Vec<[u8; 32]>,
    Vec<[u8; 32]>,
    [u32; 8],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    u32,
    [u8; 20],
    u32,
    [u32; 8],
);

/// Returns dummy test inputs for creating CLAIM notes with native types.
///
/// This is a convenience function for testing that provides realistic dummy data
/// for all the agglayer claimAsset function inputs using native types.
///
/// # Returns
/// A tuple containing native types for the new ClaimNoteParams structure
pub fn claim_note_test_inputs() -> ClaimNoteTestInputs {
    // Create SMT proofs with 32 bytes32 values each (SMT path depth)
    let smt_proof_local_exit_root = vec![[0u8; 32]; 32];
    let smt_proof_rollup_exit_root = vec![[0u8; 32]; 32];
    // Global index format: [top 5 limbs = 0, mainnet_flag = 1, rollup_index = 0, leaf_index = 2]
    let global_index = [0u32, 0, 0, 0, 0, 1, 0, 2];

    let mainnet_exit_root: [u8; 32] = [
        0x98, 0xc9, 0x11, 0xb6, 0xdc, 0xfa, 0xce, 0x93, 0xfd, 0x0b, 0xb4, 0x90, 0xd0, 0x93, 0x90,
        0xf2, 0xf7, 0xf9, 0xfc, 0xf3, 0x6f, 0xc2, 0x08, 0xcb, 0xb3, 0x65, 0x28, 0xa2, 0x29, 0x29,
        0x83, 0x26,
    ];

    let rollup_exit_root: [u8; 32] = [
        0x6a, 0x25, 0x33, 0xa2, 0x4c, 0xc2, 0xa3, 0xfe, 0xec, 0xf5, 0xc0, 0x9b, 0x6a, 0x27, 0x0b,
        0xbb, 0x24, 0xa5, 0xe2, 0xce, 0x02, 0xc1, 0x8c, 0x0e, 0x26, 0xcd, 0x54, 0xc3, 0xdd, 0xdc,
        0x2d, 0x70,
    ];

    let global_exit_root: [u8; 32] = [
        0x20, 0x7f, 0x0b, 0x7d, 0xb4, 0x88, 0xbb, 0xc4, 0x23, 0xfc, 0x3d, 0x12, 0xdb, 0x21, 0xb9,
        0x7e, 0x57, 0x44, 0x53, 0xe1, 0x2b, 0x49, 0xca, 0x21, 0x20, 0x51, 0x81, 0xaf, 0x67, 0x7d,
        0x7b, 0x04,
    ];

    let origin_network = 1u32;

    let origin_token_address: [u8; 20] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];

    let destination_network = 2u32;

    let metadata: [u32; 8] = [0; 8];

    (
        smt_proof_local_exit_root,
        smt_proof_rollup_exit_root,
        global_index,
        mainnet_exit_root,
        rollup_exit_root,
        global_exit_root,
        origin_network,
        origin_token_address,
        destination_network,
        metadata,
    )
}
