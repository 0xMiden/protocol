extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_agglayer::agglayer_library;
use miden_agglayer::claim_note::Keccak256Output;
use miden_agglayer::utils::felts_to_bytes;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_crypto::SequentialCommit;
use miden_crypto::hash::keccak::Keccak256Digest;
use miden_processor::AdviceInputs;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::TransactionContextBuilder;
use miden_tx::utils::hex_to_bytes;

use super::test_utils::{
    CLAIM_ASSET_VECTOR,
    LEAF_VALUE_VECTORS_JSON,
    LeafValueVector,
    MerkleProofVerificationFile,
    SOLIDITY_MERKLE_PROOF_VECTORS,
    execute_program_with_default_host,
    keccak_digest_to_word_strings,
};

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

/// Test get_leaf_value with claim_asset_vectors data to verify the leaf hash computation.
#[tokio::test]
async fn test_claim_asset_leaf_value() -> anyhow::Result<()> {
    let vector = &*CLAIM_ASSET_VECTOR;
    let leaf_data = vector.leaf.to_leaf_data();
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
        hex_to_bytes(&vector.leaf.leaf_value).expect("valid leaf value hex");
    let expected_leaf_value: Vec<Felt> =
        Keccak256Output::from(expected_leaf_value_bytes).to_elements();

    assert_eq!(
        computed_leaf_value, expected_leaf_value,
        "Claim asset leaf value mismatch"
    );
    Ok(())
}

/// Diagnostic: check loc_storew_be + loc_loadw_be round trip
#[tokio::test]
async fn test_loc_store_load_roundtrip() -> anyhow::Result<()> {
    let source = r#"
            use miden::core::sys
            @locals(4)
            proc test_local
                push.[10, 20, 30, 40]
                loc_storew_be.0
                dropw
                # Copy local memory to global memory for inspection
                locaddr.0
                # => [local_addr]
                padw dup.4 mem_loadw_be
                # => [WORD_FROM_LOCAL, local_addr]
                mem_storew_be.200
                dropw drop
            end
            begin
                exec.test_local
                exec.sys::truncate_stack
            end
        "#;
    let agglayer_lib = agglayer_library();
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib.clone())
        .unwrap()
        .assemble_program(source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    let ctx = miden_processor::ContextId::root();
    let err_ctx = ();
    println!("push.[10,20,30,40] → loc_storew_be.0 → read via locaddr+mem_loadw_be → mem_storew_be.200:");
    for addr in 200..204u32 {
        let val = exec_output.memory.read_element(ctx, Felt::from(addr), &err_ctx)
            .expect("readable");
        println!("  mem[{addr}] = {}", val.as_int());
    }

    Ok(())
}

/// Diagnostic: check mem_stream behavior by storing results to output memory
#[tokio::test]
async fn test_mem_stream_behavior() -> anyhow::Result<()> {
    let source = r#"
            use miden::core::sys
            begin
                # Store known data at addresses 0-7
                push.[1, 2, 3, 4] mem_storew_be.0 dropw
                push.[5, 6, 7, 8] mem_storew_be.4 dropw

                # Setup for mem_stream: [C, B, A, ptr, ...]
                padw padw padw push.0
                # => [ptr=0, A(4), B(4), C(4)]

                mem_stream
                # => [C'(4), B'(4), A(4), ptr+8]
                # C' has data from higher address (4-7), B' from lower (0-3)

                # Store C' (top 4) to output memory at 100
                mem_storew_be.100
                # => [C'(4), B'(4), A(4), ptr+8]
                
                # Store B' (next 4) - swap to get B' on top
                swapw mem_storew_be.104
                # => [B'(4), C'(4), A(4), ptr+8]

                exec.sys::truncate_stack
            end
        "#;
    let agglayer_lib = agglayer_library();
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib.clone())
        .unwrap()
        .assemble_program(source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    let ctx = miden_processor::ContextId::root();
    let err_ctx = ();
    println!("Memory: push.[1,2,3,4] at 0, push.[5,6,7,8] at 4");
    println!("C' (from higher addr 4, stored at 100):");
    for addr in 100..104u32 {
        let val = exec_output.memory.read_element(ctx, Felt::from(addr), &err_ctx).expect("readable");
        println!("  mem[{addr}] = {}", val.as_int());
    }
    println!("B' (from lower addr 0, stored at 104):");
    for addr in 104..108u32 {
        let val = exec_output.memory.read_element(ctx, Felt::from(addr), &err_ctx).expect("readable");
        println!("  mem[{addr}] = {}", val.as_int());
    }

    Ok(())
}

/// Diagnostic: check push semantics and store/load behavior
#[tokio::test]
async fn test_push_and_store_semantics() -> anyhow::Result<()> {
    // Test: what's on the stack after push.[1, 2, 3, 4]?
    // And what does mem_storew_be store?
    let source = r#"
            use miden::core::sys
            begin
                push.[1, 2, 3, 4]
                mem_storew_be.0
                # Also test push.5.6.7.8
                dropw
                push.5.6.7.8
                mem_storew_be.4
                dropw

                # Now load and check
                padw mem_loadw_be.0
                # What's on the stack?
                exec.sys::truncate_stack
            end
        "#;
    let agglayer_lib = agglayer_library();
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib.clone())
        .unwrap()
        .assemble_program(source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    println!("After push.[1,2,3,4] + mem_storew_be.0 + mem_loadw_be.0:");
    for i in 0..4 {
        println!("  stack[{i}] = {}", exec_output.stack[i].as_int());
    }

    // Check individual memory elements
    let ctx = miden_processor::ContextId::root();
    let err_ctx = ();
    println!("Memory from push.[1,2,3,4] mem_storew_be.0:");
    for addr in 0..4u32 {
        let val = exec_output.memory.read_element(ctx, Felt::from(addr), &err_ctx)
            .expect("readable");
        println!("  word[{addr}] = {}", val.as_int());
    }
    println!("Memory from push.5.6.7.8 mem_storew_be.4:");
    for addr in 4..8u32 {
        let val = exec_output.memory.read_element(ctx, Felt::from(addr), &err_ctx)
            .expect("readable");
        println!("  word[{addr}] = {}", val.as_int());
    }

    Ok(())
}

/// Diagnostic: check mem_stream and mem_load_double_word behavior with specific data
#[tokio::test]
async fn test_mem_read_ordering() -> anyhow::Result<()> {
    let source = r#"
            use miden::core::sys
            use miden::agglayer::utils
            begin
                # Store data to memory
                push.[100, 101, 102, 103] mem_storew_be.0 dropw
                push.[104, 105, 106, 107] mem_storew_be.4 dropw
                
                # Read back with mem_load_double_word (uses mem_loadw_be)
                push.0
                exec.utils::mem_load_double_word
                # => [WORD_1, WORD_2]
                
                exec.sys::truncate_stack
            end
        "#;
    let agglayer_lib = agglayer_library();
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib.clone())
        .unwrap()
        .assemble_program(source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;

    println!("Stored: push.[100,101,102,103] at 0, push.[104,105,106,107] at 4");
    println!("After mem_load_double_word(0):");
    for i in 0..8 {
        println!("  stack[{i}] = {}", exec_output.stack[i].as_int());
    }

    Ok(())
}

/// Test verify_merkle_proof with data loaded from advice map (not verify_leaf_bridge).
/// This tests whether pipe_preimage_to_memory → mem_stream produces the right format.
#[tokio::test]
async fn test_claim_asset_merkle_proof_via_advice_map() -> anyhow::Result<()> {
    let vector = &*CLAIM_ASSET_VECTOR;
    let proof_data = vector.proof.to_proof_data();

    // Get just the 256 elements of the local exit root proof (32 nodes × 8 felts)
    // Fully reversed to match the format that keccak_digest_to_word_strings produces
    let proof_elements: Vec<Felt> = proof_data
        .smt_proof_local_exit_root
        .iter()
        .flat_map(|node| node.to_memory_elements())
        .collect();
    assert_eq!(proof_elements.len(), 256);

    // Get the mainnet exit root (8 felts) - per-word reversed to match
    // mem_load_double_word which uses mem_loadw_be (per-word reversal)
    let root_elements = proof_data.mainnet_exit_root.to_word_reversed_elements();

    // Combine proof + root into one advice map entry (264 felts = 66 words)
    let mut combined = Vec::with_capacity(264);
    combined.extend(&proof_elements); // 256 felts
    combined.extend(&root_elements);  // 8 felts
    let combined_key: Word = miden_crypto::hash::rpo::Rpo256::hash_elements(&combined);

    let advice_inputs = AdviceInputs::default().with_map(vec![
        (combined_key, combined),
    ]);

    // Build the leaf value string for push.[]
    let leaf_digest = Keccak256Digest::try_from(vector.leaf.leaf_value.as_str()).unwrap();
    let (leaf_hi, leaf_lo) = keccak_digest_to_word_strings(leaf_digest);

    // Extract leaf index
    let gi_hex = &vector.proof.global_index;
    let leaf_index = u32::from_str_radix(&gi_hex[gi_hex.len() - 8..], 16).unwrap();

    let source = format!(
        r#"
        use miden::core::mem
        use miden::agglayer::crypto_utils

        begin
            # Load proof + root from advice map
            push.{combined_key}
            adv.push_mapval
            push.0 push.66
            exec.mem::pipe_preimage_to_memory drop

            # Prepare stack for verify_merkle_proof
            # Expected root is at memory address 256 (after 32 nodes × 8 felts)
            push.256                          # expected root memory pointer
            push.{leaf_index}                 # provided leaf index
            push.0                            # Merkle path memory pointer
            push.[{leaf_hi}] push.[{leaf_lo}] # provided leaf value (keccak_digest format)
            # => [LEAF_VALUE_LO, LEAF_VALUE_HI, merkle_path_ptr, leaf_idx, expected_root_ptr]

            exec.crypto_utils::verify_merkle_proof
            assert.err="advice map merkle proof verification failed"
        end
    "#
    );

    let agglayer_lib = agglayer_library();
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib)
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    execute_program_with_default_host(program, Some(advice_inputs))
        .await
        .map_err(|e| anyhow::anyhow!("merkle proof via advice map failed: {e}"))?;

    Ok(())
}


/// Test verify_merkle_proof with claim_asset_vectors data using the same
/// direct memory storage approach as test_solidity_verify_merkle_proof_compatibility.
#[tokio::test]
async fn test_claim_asset_merkle_proof_direct() -> anyhow::Result<()> {
    let vector = &*CLAIM_ASSET_VECTOR;

    // Build MASM code that stores the data directly in memory (same approach as working test)
    let mut store_path_source = String::new();
    for height in 0..32 {
        let path_node_hex = &vector.proof.smt_proof_local_exit_root[height];
        let path_node = Keccak256Digest::try_from(path_node_hex.as_str()).unwrap();
        let (node_hi, node_lo) = keccak_digest_to_word_strings(path_node);
        store_path_source.push_str(&format!(
            "
\tpush.[{node_hi}] mem_storew_be.{} dropw
\tpush.[{node_lo}] mem_storew_be.{} dropw
    ",
            height * 8,
            height * 8 + 4
        ));
    }

    // Prepare the expected root (mainnet_exit_root)
    let root = Keccak256Digest::try_from(vector.proof.mainnet_exit_root.as_str()).unwrap();
    let (root_hi, root_lo) = keccak_digest_to_word_strings(root);

    // Prepare the leaf value
    let leaf = Keccak256Digest::try_from(vector.leaf.leaf_value.as_str()).unwrap();
    let (leaf_hi, leaf_lo) = keccak_digest_to_word_strings(leaf);

    // Extract leaf index from global index
    let gi_hex = &vector.proof.global_index;
    let leaf_index = u32::from_str_radix(&gi_hex[gi_hex.len() - 8..], 16).unwrap();

    let source = format!(
        r#"
        use miden::agglayer::crypto_utils

        begin
            # store the merkle path to the memory
            {store_path_source}
            # => []

            # store the root to the memory (double word slot 256)
            push.[{root_lo}] mem_storew_be.256 dropw
            push.[{root_hi}] mem_storew_be.260 dropw
            # => []

            # prepare the stack for verify_merkle_proof
            push.256                          # expected root memory pointer
            push.{leaf_index}                 # provided leaf index
            push.0                            # Merkle path memory pointer
            push.[{leaf_hi}] push.[{leaf_lo}] # provided leaf value
            # => [LEAF_VALUE_LO, LEAF_VALUE_HI, merkle_path_ptr, leaf_idx, expected_root_ptr]

            exec.crypto_utils::verify_merkle_proof
            # => [verification_flag]

            assert.err="claim asset merkle proof verification failed"
            # => []
        end
    "#
    );

    let tx_script = CodeBuilder::new()
        .with_statically_linked_library(&agglayer_library())?
        .compile_tx_script(source)?;

    TransactionContextBuilder::with_existing_mock_account()
        .tx_script(tx_script.clone())
        .build()?
        .execute()
        .await
        .context("failed to verify claim asset merkle proof")?;

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
