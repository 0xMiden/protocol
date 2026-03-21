extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_agglayer::agglayer_library;
use miden_agglayer::claim_note::Keccak256Output;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_crypto::SequentialCommit;
use miden_processor::advice::AdviceInputs;
use miden_processor::utils::packed_u32_elements_to_bytes;
use miden_protocol::{Felt, Word};
use miden_tx::utils::hex_to_bytes;

use super::test_utils::{
    LEAF_VALUE_VECTORS_JSON,
    LeafValueVector,
    execute_program_with_default_host,
};

// HELPER FUNCTIONS
// ================================================================================================

fn felts_to_le_bytes(limbs: &[Felt]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(limbs.len() * 4);
    for limb in limbs.iter() {
        let u32_value = limb.as_canonical_u64() as u32;
        bytes.extend_from_slice(&u32_value.to_le_bytes());
    }
    bytes
}

// TESTS
// ================================================================================================

/// Test that the `pack_leaf_data` procedure produces the correct byte layout.
#[tokio::test]
async fn pack_leaf_data() -> anyhow::Result<()> {
    let vector: LeafValueVector =
        serde_json::from_str(LEAF_VALUE_VECTORS_JSON).expect("failed to parse leaf value vector");

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
    let leaf_data_bytes: Vec<u8> = packed_u32_elements_to_bytes(&leaf_data_elements);
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
            use agglayer::bridge::leaf_utils

            const LEAF_DATA_START_PTR = 0
            const CLAIM_LEAF_DATA_WORD_LEN = 8

            begin
                push.{key}

                adv.push_mapval
                push.LEAF_DATA_START_PTR push.CLAIM_LEAF_DATA_WORD_LEN
                exec.mem::pipe_preimage_to_memory drop

                exec.leaf_utils::pack_leaf_data
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

    let packed_elements: Vec<Felt> = (0..29u32)
        .map(|addr| {
            exec_output
                .memory
                .read_element(ctx, Felt::from(addr))
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
        serde_json::from_str(LEAF_VALUE_VECTORS_JSON).expect("failed to parse leaf value vector");

    let leaf_data = vector.to_leaf_data();
    let key: Word = leaf_data.to_commitment();
    let advice_inputs = AdviceInputs::default().with_map(vec![(key, leaf_data.to_elements())]);

    let source = format!(
        r#"
            use miden::core::sys
            use agglayer::bridge::bridge_in

            begin
                push.{key}
                exec.bridge_in::get_leaf_value
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
