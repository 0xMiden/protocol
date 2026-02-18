extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_agglayer::agglayer_library;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_core_lib::handlers::bytes_to_packed_u32_felts;
use miden_core_lib::handlers::keccak256::KeccakPreimage;
use miden_crypto::FieldElement;
use miden_crypto::hash::keccak::Keccak256Digest;
use miden_processor::AdviceInputs;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::TransactionContextBuilder;
use serde::Deserialize;

use super::test_utils::{execute_program_with_default_host, keccak_digest_to_word_strings};

// LEAF_DATA_NUM_WORDS is defined as 8 in crypto_utils.masm, representing 8 Miden words of 4 felts
// each
const LEAF_DATA_FELTS: usize = 32;

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

fn u32_words_to_solidity_bytes32_hex(words: &[u64]) -> String {
    assert_eq!(words.len(), 8, "expected 8 u32 words = 32 bytes");
    let mut out = [0u8; 32];

    for (i, &w) in words.iter().enumerate() {
        let le = (w as u32).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&le);
    }

    let mut s = String::from("0x");
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// Helper: parse 0x-prefixed hex into a fixed-size byte array
fn hex_to_fixed<const N: usize>(s: &str) -> [u8; N] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(s.len(), N * 2, "expected {} hex chars", N * 2);
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[tokio::test]
async fn test_keccak_hash_get_leaf_value() -> anyhow::Result<()> {
    let agglayer_lib = agglayer_library();

    // === Values from hardhat test ===
    let leaf_type: u8 = 0;
    let origin_network: u32 = 0;
    let token_address: [u8; 20] = hex_to_fixed("0x1234567890123456789012345678901234567890");
    let destination_network: u32 = 1;
    let destination_address: [u8; 20] = hex_to_fixed("0x0987654321098765432109876543210987654321");
    let amount_u64: u64 = 1; // 1e19
    let metadata_hash: [u8; 32] =
        hex_to_fixed("0x2cdc14cacf6fec86a549f0e4d01e83027d3b10f29fa527c1535192c1ca1aac81");

    // Expected hash value from Solidity implementation
    let expected_hash = "0xf6825f6c59be2edf318d7251f4b94c0e03eb631b76a0e7b977fd8ed3ff925a3f";

    // abi.encodePacked(
    //   uint8, uint32, address, uint32, address, uint256, bytes32
    // )
    let mut amount_u256_be = [0u8; 32];
    amount_u256_be[24..32].copy_from_slice(&amount_u64.to_be_bytes());

    let mut input_u8 = Vec::with_capacity(113);
    input_u8.push(leaf_type);
    input_u8.extend_from_slice(&origin_network.to_be_bytes());
    input_u8.extend_from_slice(&token_address);
    input_u8.extend_from_slice(&destination_network.to_be_bytes());
    input_u8.extend_from_slice(&destination_address);
    input_u8.extend_from_slice(&amount_u256_be);
    input_u8.extend_from_slice(&metadata_hash);

    let len_bytes = input_u8.len();
    assert_eq!(len_bytes, 113);

    let preimage = KeccakPreimage::new(input_u8.clone());
    let mut input_felts = bytes_to_packed_u32_felts(&input_u8);
    // Pad to LEAF_DATA_FELTS (128 bytes) as expected by the downstream code
    input_felts.resize(LEAF_DATA_FELTS, Felt::ZERO);
    assert_eq!(input_felts.len(), LEAF_DATA_FELTS);

    // Arbitrary key to store input in advice map (in prod this is RPO(input_felts))
    let key: Word = Hasher::hash_elements(&input_felts);
    let advice_inputs = AdviceInputs::default().with_map(vec![(key, input_felts)]);

    let source = format!(
        r#"
            use miden::core::sys
            use miden::core::crypto::hashes::keccak256
            use miden::agglayer::crypto_utils

            begin
                push.{key}

                exec.crypto_utils::get_leaf_value
                exec.sys::truncate_stack
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

    let digest: Vec<u64> = exec_output.stack[0..8].iter().map(|f| f.as_int()).collect();
    let hex_digest = u32_words_to_solidity_bytes32_hex(&digest);

    let keccak256_digest: Vec<u64> = preimage.digest().as_ref().iter().map(Felt::as_int).collect();
    let keccak256_hex_digest = u32_words_to_solidity_bytes32_hex(&keccak256_digest);

    assert_eq!(digest, keccak256_digest);
    assert_eq!(hex_digest, keccak256_hex_digest);
    assert_eq!(hex_digest, expected_hash);
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

// HELPER FUNCTIONS
// ================================================================================================

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
