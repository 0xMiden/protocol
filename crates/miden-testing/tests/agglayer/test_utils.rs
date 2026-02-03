extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use miden_agglayer::agglayer_library;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_core_lib::handlers::bytes_to_packed_u32_felts;
use miden_core_lib::handlers::keccak256::KeccakPreimage;
use miden_processor::fast::{ExecutionOutput, FastProcessor};
use miden_processor::{AdviceInputs, DefaultHost, ExecutionError, Program, StackInputs};
use miden_protocol::Felt;
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
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    let rollup_exit_root: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
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
        origin_network,
        origin_token_address,
        destination_network,
        metadata,
    )
}

// KECCAK FELT ORDERING TESTS
// ================================================================================================

/// Test 1: Keccak output ordering vs bytes32 packing
///
/// This test verifies that the keccak256::hash_bytes MASM output matches the Rust-side
/// `KeccakPreimage::digest()` → `bytes_to_packed_u32_felts()` conversion exactly.
/// It also asserts that the "reverse-within-word" variant does NOT match, pinning down
/// that no within-word reversal is needed.
#[tokio::test]
async fn test_keccak_output_ordering_vs_bytes32_packing() -> anyhow::Result<()> {
    // Pick a fixed 32-byte input: 0x00..0x1f
    let input_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);

    // Compute the expected keccak digest bytes in Rust via KeccakPreimage
    let preimage = KeccakPreimage::new(input_bytes.to_vec());
    let expected_digest_felts: Vec<Felt> = preimage.digest().as_ref().to_vec();

    // Convert input bytes to packed u32 felts for memory initialization
    let input_felts = bytes_to_packed_u32_felts(&input_bytes);
    assert_eq!(input_felts.len(), 8, "32 bytes should produce 8 u32 felts");

    // Build memory initialization: store each felt at memory addresses 0..7
    let mem_init: Vec<String> = input_felts
        .iter()
        .enumerate()
        .map(|(i, f)| format!("push.{} mem_store.{}", f.as_int(), i))
        .collect();
    let mem_init_code = mem_init.join("\n                ");

    // Assemble a tiny MASM program that:
    // - mem_stores the packed input felts into memory addresses 0..7
    // - calls exec.keccak256::hash_bytes with [start_ptr=0, len_bytes=32]
    // - truncates the stack
    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::keccak256

            begin
                # Initialize memory with input felts
                {mem_init_code}

                # Call keccak256::hash_bytes with start_ptr=0, len_bytes=32
                push.32 push.0
                # => [start_ptr=0, len_bytes=32]
                exec.keccak256::hash_bytes
                # => [DIGEST[8]]

                exec.sys::truncate_stack
            end
        "#
    );

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_library())
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    // The top 8 stack felts should equal the expected packed digest felts
    let result_digest: Vec<Felt> = exec_output.stack[0..8].to_vec();

    assert_eq!(
        result_digest, expected_digest_felts,
        "Keccak output should match bytes_to_packed_u32_felts(digest_bytes)"
    );

    // Compute the "reverse-within-word" variant (reverse each 4-felt chunk)
    // This is what some code was doing: reversing felts within each word
    let reversed_within_word: Vec<Felt> = expected_digest_felts
        .chunks(4)
        .flat_map(|chunk| chunk.iter().rev().copied())
        .collect();

    // Assert that the reversed variant does NOT match (regression pin)
    assert_ne!(
        result_digest, reversed_within_word,
        "Keccak output should NOT match reverse-within-word variant - \
         this confirms no within-word reversal is needed"
    );

    Ok(())
}

/// Test 2: Raw bytes→felts load/return ordering
///
/// This test verifies that when we store packed u32 felts to memory and load them back
/// using mem_loadw_be, we get exactly the same felts without any within-word reversal.
#[tokio::test]
async fn test_raw_bytes_to_felts_load_return_ordering() -> anyhow::Result<()> {
    // Use the same 32-byte input: 0x00..0x1f
    let input_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);

    // Compute input_felts = bytes_to_packed_u32_felts(&input_bytes)
    let input_felts = bytes_to_packed_u32_felts(&input_bytes);
    assert_eq!(input_felts.len(), 8, "32 bytes should produce 8 u32 felts");

    // Build memory initialization: store each felt at memory addresses 0..7
    let mem_init: Vec<String> = input_felts
        .iter()
        .enumerate()
        .map(|(i, f)| format!("push.{} mem_store.{}", f.as_int(), i))
        .collect();
    let mem_init_code = mem_init.join("\n                ");

    // Assemble a tiny MASM program that:
    // - mem_stores input_felts into memory 0..7
    // - loads them back onto the stack as two words using mem_loadw_be
    // - truncates the stack
    //
    // Note: mem_loadw_be.4 loads the word at address 4 (felts 4-7)
    //       mem_loadw_be.0 loads the word at address 0 (felts 0-3)
    // After both loads, stack has [felts_0_3, felts_4_7] but we need [felts_4_7, felts_0_3]
    // to match the original ordering when reading from stack (stack is LIFO)
    let source = format!(
        r#"
            use miden::core::sys

            begin
                # Initialize memory with input felts at addresses 0..7
                {mem_init_code}

                # Load felts back from memory
                # mem_loadw_be loads a word (4 felts) from memory
                # We load address 0 first, then address 4
                # Stack grows downward, so first loaded is at bottom

                padw mem_loadw_be.0
                # => [felt_3, felt_2, felt_1, felt_0]

                padw mem_loadw_be.4
                # => [felt_7, felt_6, felt_5, felt_4, felt_3, felt_2, felt_1, felt_0]

                exec.sys::truncate_stack
            end
        "#
    );

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    // The top 8 stack felts should represent the loaded values
    let result_felts: Vec<Felt> = exec_output.stack[0..8].to_vec();

    // mem_loadw_be loads [felt_n+3, felt_n+2, felt_n+1, felt_n] for address n
    // After loading address 0: stack = [felt_3, felt_2, felt_1, felt_0]
    // After loading address 4: stack = [felt_7, felt_6, felt_5, felt_4, felt_3, felt_2, felt_1,
    // felt_0] So the stack top-to-bottom is: felt_7, felt_6, felt_5, felt_4, felt_3, felt_2,
    // felt_1, felt_0 which is: [input_felts[7], input_felts[6], ..., input_felts[0]]
    let expected_stack: Vec<Felt> = input_felts.iter().rev().copied().collect();

    assert_eq!(
        result_felts, expected_stack,
        "Loaded felts should match input_felts in reverse order (stack LIFO)"
    );

    // Also verify that if we compare without reversal, it does NOT match
    // (unless the input happens to be symmetric, which it isn't for 0x00..0x1f)
    assert_ne!(
        result_felts, input_felts,
        "Stack result should not equal input_felts directly (due to LIFO ordering)"
    );

    Ok(())
}
