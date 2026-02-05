extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_agglayer::claim_note::Keccak256Output;
use miden_agglayer::utils::felts_to_bytes;
use miden_agglayer::{EthAddressFormat, EthAmount, LeafData, MetadataHash, agglayer_library};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_crypto::SequentialCommit;
use miden_crypto::hash::keccak::Keccak256Digest;
use miden_processor::AdviceInputs;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::TransactionContextBuilder;
use miden_tx::utils::hex_to_bytes;
use serde::Deserialize;

use super::test_utils::{execute_program_with_default_host, keccak_digest_to_word_strings};

/// Merkle proof verification vectors JSON embedded at compile time from the Foundry-generated file.
const MERKLE_PROOF_VECTORS_JSON: &str =
    include_str!("../../../miden-agglayer/solidity-compat/test-vectors/merkle_proof_vectors.json");

/// Deserialized Merkle proof vectors from Solidity DepositContractBase.sol
/// Uses parallel arrays for leaves and roots. For each element from leaves/roots there are 32
/// elements from merkle_paths, which represent the merkle path for that leaf + root.
#[derive(Debug, Deserialize)]
struct MerkleProofVerificationFile {
    leaves: Vec<String>,
    roots: Vec<String>,
    merkle_paths: Vec<String>,
}

/// Lazily parsed Merkle proof vectors from the JSON file.
static SOLIDITY_MERKLE_PROOF_VECTORS: LazyLock<MerkleProofVerificationFile> = LazyLock::new(|| {
    serde_json::from_str(MERKLE_PROOF_VECTORS_JSON)
        .expect("failed to parse Merkle proof vectors JSON")
});

/// Leaf data test vectors JSON embedded at compile time from the Foundry-generated file.
const LEAF_VALUE_VECTORS_JSON: &str =
    include_str!("../../../miden-agglayer/solidity-compat/test-vectors/leaf_value_vectors.json");

// TEST VECTOR STRUCTURES
// ================================================================================================

/// Deserialized leaf value test vector from Solidity-generated JSON.
#[derive(Debug, Deserialize)]
struct LeafValueVector {
    origin_network: u32,
    origin_token_address: String,
    destination_network: u32,
    destination_address: String,
    amount: String,
    metadata_hash: String,
    #[allow(dead_code)]
    leaf_value: String,
}

impl LeafValueVector {
    /// Converts this test vector into a `LeafData` instance.
    fn to_leaf_data(&self) -> LeafData {
        LeafData {
            origin_network: self.origin_network,
            origin_token_address: EthAddressFormat::from_hex(&self.origin_token_address)
                .expect("valid origin token address hex"),
            destination_network: self.destination_network,
            destination_address: EthAddressFormat::from_hex(&self.destination_address)
                .expect("valid destination address hex"),
            amount: EthAmount::new(hex_to_bytes(&self.amount).expect("valid amount hex")),
            metadata_hash: MetadataHash::new(
                hex_to_bytes(&self.metadata_hash).expect("valid metadata hash hex"),
            ),
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn felts_to_le_bytes(limbs: &[Felt]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(limbs.len() * 4);
    for limb in limbs.iter() {
        let u32_value = limb.as_int() as u32;
        bytes.extend_from_slice(&u32_value.to_le_bytes());
    }
    bytes
}

fn merkle_proof_verification_code(
    index: usize,
    merkle_paths: &MerkleProofVerificationFile,
) -> String {
    // generate the code which stores the merkle path to the memory
    let mut store_path_source = String::new();
    for height in 0..32 {
        let path_node =
            Keccak256Digest::try_from(merkle_paths.merkle_paths[index * 32 + height].as_str())
                .unwrap();
        let (node_hi, node_lo) = keccak_digest_to_word_strings(path_node);
        // each iteration (each index in leaf/root vector) we rewrite the merkle path nodes, so the
        // memory pointers for the merkle path and the expected root never change
        store_path_source.push_str(&format!(
            "
\tpush.[{node_hi}] mem_storew_be.{} dropw
\tpush.[{node_lo}] mem_storew_be.{} dropw
    ",
            height * 8,
            height * 8 + 4
        ));
    }

    // prepare the root for the provided index
    let root = Keccak256Digest::try_from(merkle_paths.roots[index].as_str()).unwrap();
    let (root_hi, root_lo) = keccak_digest_to_word_strings(root);

    // prepare the leaf for the provided index
    let leaf = Keccak256Digest::try_from(merkle_paths.leaves[index].as_str()).unwrap();
    let (leaf_hi, leaf_lo) = keccak_digest_to_word_strings(leaf);

    format!(
        r#"
        use miden::agglayer::crypto_utils

        begin
            # store the merkle path to the memory (double word slots from 0 to 248)
            {store_path_source}
            # => []

            # store the root to the memory (double word slot 256)
            push.[{root_lo}] mem_storew_be.256 dropw
            push.[{root_hi}] mem_storew_be.260 dropw
            # => []

            # prepare the stack for the `verify_merkle_proof` procedure
            push.256                          # expected root memory pointer
            push.{index}                      # provided leaf index
            push.0                            # Merkle path memory pointer
            push.[{leaf_hi}] push.[{leaf_lo}] # provided leaf value
            # => [LEAF_VALUE_LO, LEAF_VALUE_HI, merkle_path_ptr, leaf_idx, expected_root_ptr]

            exec.crypto_utils::verify_merkle_proof
            # => [verification_flag]

            assert.err="verification failed"
            # => []
        end
    "#
    )
}

// TESTS
// ================================================================================================

/// Test that the `pack_leaf_data` procedure produces the correct byte layout.
#[tokio::test]
async fn pack_leaf_data() -> anyhow::Result<()> {
    let vector: LeafValueVector =
        serde_json::from_str(LEAF_VALUE_VECTORS_JSON).expect("Failed to parse leaf value vector");

    let leaf_data = vector.to_leaf_data();

    // Build expected bytes
    let mut expected_packed_bytes: Vec<u8> = Vec::new();
    expected_packed_bytes.push(0u8);
    expected_packed_bytes.extend_from_slice(&leaf_data.origin_network.to_be_bytes());
    expected_packed_bytes.extend_from_slice(leaf_data.origin_token_address.as_bytes());
    expected_packed_bytes.extend_from_slice(&leaf_data.destination_network.to_be_bytes());
    expected_packed_bytes.extend_from_slice(leaf_data.destination_address.as_bytes());
    expected_packed_bytes.extend_from_slice(leaf_data.amount.as_bytes());
    let metadata_hash_bytes: [u8; 32] = hex_to_bytes(&vector.metadata_hash).unwrap();
    expected_packed_bytes.extend_from_slice(&metadata_hash_bytes);
    assert_eq!(expected_packed_bytes.len(), 113);

    let agglayer_lib = agglayer_library();
    let leaf_data_elements = leaf_data.to_elements();
    let leaf_data_bytes: Vec<u8> = felts_to_bytes(&leaf_data_elements);
    assert_eq!(
        leaf_data_bytes.len(),
        128,
        "expected 8 words * 4 felts * 4 bytes per felt = 128 bytes"
    );
    assert_eq!(leaf_data_bytes[116..], vec![0; 12], "the last 3 felts are pure padding");
    assert_eq!(leaf_data_bytes[3], expected_packed_bytes[0], "the first byte is the leaf type");
    assert_eq!(
        leaf_data_bytes[4..8],
        expected_packed_bytes[1..5],
        "the next 4 bytes are the origin network"
    );
    assert_eq!(
        leaf_data_bytes[8..28],
        expected_packed_bytes[5..25],
        "the next 20 bytes are the origin token address"
    );
    assert_eq!(
        leaf_data_bytes[28..32],
        expected_packed_bytes[25..29],
        "the next 4 bytes are the destination network"
    );
    assert_eq!(
        leaf_data_bytes[32..52],
        expected_packed_bytes[29..49],
        "the next 20 bytes are the destination address"
    );
    assert_eq!(
        leaf_data_bytes[52..84],
        expected_packed_bytes[49..81],
        "the next 32 bytes are the amount"
    );
    assert_eq!(
        leaf_data_bytes[84..116],
        expected_packed_bytes[81..113],
        "the next 32 bytes are the metadata hash"
    );

    assert_eq!(leaf_data_bytes[3..116], expected_packed_bytes, "byte packing is as expected");

    let key: Word = leaf_data.to_commitment();
    let advice_inputs = AdviceInputs::default().with_map(vec![(key, leaf_data_elements.clone())]);

    let source = format!(
        r#"
            use miden::core::mem
            use miden::agglayer::crypto_utils

            const LEAF_DATA_START_PTR = 0
            const LEAF_DATA_NUM_WORDS = 8

            begin
                push.{key}

                adv.push_mapval
                push.LEAF_DATA_START_PTR push.LEAF_DATA_NUM_WORDS
                exec.mem::pipe_preimage_to_memory drop

                exec.crypto_utils::pack_leaf_data
            end
        "#
    );

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib.clone())
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, Some(advice_inputs)).await?;

    // Read packed elements from memory at addresses 0..29
    let ctx = miden_processor::ContextId::root();
    let err_ctx = ();

    let packed_elements: Vec<Felt> = (0..29u32)
        .map(|addr| {
            exec_output
                .memory
                .read_element(ctx, Felt::from(addr), &err_ctx)
                .expect("address should be valid")
        })
        .collect();

    let packed_bytes: Vec<u8> = felts_to_le_bytes(&packed_elements);

    // push 3 more zero bytes for packing, since `pack_leaf_data` should leave us with the last 3
    // bytes set to 0 (prep for hashing, where padding bytes must be 0)
    expected_packed_bytes.extend_from_slice(&[0u8; 3]);

    assert_eq!(
        &packed_bytes, &expected_packed_bytes,
        "Packed bytes don't match expected Solidity encoding"
    );

    Ok(())
}

#[tokio::test]
async fn get_leaf_value() -> anyhow::Result<()> {
    let vector: LeafValueVector =
        serde_json::from_str(LEAF_VALUE_VECTORS_JSON).expect("Failed to parse leaf value vector");

    let leaf_data = vector.to_leaf_data();
    let key: Word = leaf_data.to_commitment();
    let advice_inputs = AdviceInputs::default().with_map(vec![(key, leaf_data.to_elements())]);

    let source = format!(
        r#"
            use miden::core::mem
            use miden::core::sys
            use miden::agglayer::crypto_utils

            begin
                push.{key}
                exec.crypto_utils::get_leaf_value
                exec.sys::truncate_stack
            end
        "#
    );
    let agglayer_lib = agglayer_library();

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib.clone())
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, Some(advice_inputs)).await?;
    let computed_leaf_value: Vec<Felt> = exec_output.stack[0..8].to_vec();
    let expected_leaf_value_bytes: [u8; 32] =
        hex_to_bytes(&vector.leaf_value).expect("valid leaf value hex");
    let expected_leaf_value: Vec<Felt> =
        Keccak256Output::from(expected_leaf_value_bytes).to_elements();

    assert_eq!(computed_leaf_value, expected_leaf_value);
    Ok(())
}

#[tokio::test]
async fn test_solidity_verify_merkle_proof_compatibility() -> anyhow::Result<()> {
    let merkle_paths = &*SOLIDITY_MERKLE_PROOF_VECTORS;

    // Validate array lengths
    assert_eq!(merkle_paths.leaves.len(), merkle_paths.roots.len());
    // paths have 32 nodes for each leaf/root, so the overall paths length should be 32 times longer
    // than leaves/roots length
    assert_eq!(merkle_paths.leaves.len() * 32, merkle_paths.merkle_paths.len());

    for leaf_index in 0..32 {
        let source = merkle_proof_verification_code(leaf_index, merkle_paths);

        let tx_script = CodeBuilder::new()
            .with_statically_linked_library(&agglayer_library())?
            .compile_tx_script(source)?;

        TransactionContextBuilder::with_existing_mock_account()
            .tx_script(tx_script.clone())
            .build()?
            .execute()
            .await
            .context(format!("failed to execute transaction with leaf index {leaf_index}"))?;
    }

    Ok(())
}
