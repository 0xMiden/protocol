extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use miden_agglayer::agglayer_library;
use miden_core_lib::CoreLibrary;
use miden_crypto::hash::keccak::Keccak256Digest;
use miden_processor::fast::{ExecutionOutput, FastProcessor};
use miden_processor::{AdviceInputs, DefaultHost, ExecutionError, Felt, Program, StackInputs};
use miden_protocol::transaction::TransactionKernel;

/// Transforms the `[Keccak256Digest]` into two word strings: (`a, b, c, d`, `e, f, g, h`)
pub fn keccak_digest_to_word_strings(digest: Keccak256Digest) -> (String, String) {
    let double_word = (*digest)
        .chunks(4)
        .map(|chunk| Felt::from(u32::from_le_bytes(chunk.try_into().unwrap())).to_string())
        .rev()
        .collect::<Vec<_>>();

    (double_word[0..4].join(", "), double_word[4..8].join(", "))
}

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

/*
// TODO: Uncomment this when https://github.com/0xMiden/miden-base/issues/2397 is ready.
// The mainnet exit root is hardcoded to pass the current test (i.e. we set the expected mainnet
// root to whatever the current implementation computes), and changing any impl. details will break
// the test, forcing us to artificially change the expected root every time.
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
/// - metadata: [u8; 32]
pub type ClaimNoteTestInputs = (
    Vec<[u8; 32]>,
    Vec<[u8; 32]>,
    [u32; 8],
    [u8; 32],
    [u8; 32],
    u32,
    [u8; 20],
    u32,
    [u8; 32],
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
        0x05, 0xc2, 0xbe, 0x9d, 0xd7, 0xf4, 0x7e, 0xc6, 0x29, 0xae, 0x6a, 0xc1, 0x1a, 0x24, 0xb5,
        0x28, 0x59, 0xfd, 0x35, 0x8c, 0x31, 0x39, 0x00, 0xf5, 0x23, 0x1f, 0x84, 0x58, 0x63, 0x22,
        0xb5, 0x06,
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

    let metadata_hash: [u8; 32] = [0u8; 32];

    (
        smt_proof_local_exit_root,
        smt_proof_rollup_exit_root,
        global_index,
        mainnet_exit_root,
        rollup_exit_root,
        origin_network,
        origin_token_address,
        destination_network,
        metadata_hash,
    )
}
*/
