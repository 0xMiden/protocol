extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_agglayer::{EthAddress, LeafValue, MetadataHash, agglayer_library};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_crypto::SequentialCommit;
use miden_crypto::hash::keccak::Keccak256;
use miden_processor::advice::AdviceInputs;
use miden_processor::utils::{bytes_to_packed_u32_elements, packed_u32_elements_to_bytes};
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
    let expected_leaf_value: Vec<Felt> = LeafValue::from(expected_leaf_value_bytes).to_elements();

    assert_eq!(computed_leaf_value, expected_leaf_value);
    Ok(())
}

/// Verifies that manually storing leaf data with leafType=1 (message) and calling
/// `compute_leaf_value` produces the same Keccak256 hash as the Rust-side computation.
///
/// This isolates the MASM hash pipeline from the full bridge_message flow.
#[tokio::test]
async fn compute_leaf_value_message_type() -> anyhow::Result<()> {
    let origin_network = 77u32;
    let destination_network = 1u32;
    let origin_address = EthAddress::new([0u8; 20]);
    let destination_address = EthAddress::new([0u8; 20]);
    let metadata_hash = MetadataHash::new([0x42u8; 32]);

    // Byte-swap network IDs to LE (matching MASM convention)
    let leaf_type_swapped = u32::from_le_bytes(1u32.to_be_bytes());
    let origin_network_swapped = u32::from_le_bytes(origin_network.to_be_bytes());
    let dest_network_swapped = u32::from_le_bytes(destination_network.to_be_bytes());
    let origin_addr_felts = origin_address.to_elements();
    let dest_addr_felts = destination_address.to_elements();
    let mh: Vec<u64> = metadata_hash.to_elements().iter().map(|f| f.as_canonical_u64()).collect();

    // Build expected packed bytes (113 bytes, abi.encodePacked)
    let mut packed = Vec::with_capacity(113);
    packed.push(1u8);
    packed.extend_from_slice(&origin_network.to_be_bytes());
    packed.extend_from_slice(origin_address.as_bytes());
    packed.extend_from_slice(&destination_network.to_be_bytes());
    packed.extend_from_slice(destination_address.as_bytes());
    packed.extend_from_slice(&[0u8; 32]);
    packed.extend_from_slice(metadata_hash.as_bytes());
    assert_eq!(packed.len(), 113);

    let expected_hash = Keccak256::hash(&packed);
    let expected_felts: Vec<Felt> = bytes_to_packed_u32_elements(expected_hash.as_bytes());

    // Build MASM program that stores leaf data manually, then calls compute_leaf_value
    let source = format!(
        r#"
            use miden::core::sys
            use agglayer::bridge::leaf_utils

            begin
                push.{leaf_type_swapped} push.0 mem_store
                push.{origin_network_swapped} push.1 mem_store
                push.{oa0} push.2 mem_store
                push.{oa1} push.3 mem_store
                push.{oa2} push.4 mem_store
                push.{oa3} push.5 mem_store
                push.{oa4} push.6 mem_store
                push.{dest_network_swapped} push.7 mem_store
                push.{da0} push.8 mem_store
                push.{da1} push.9 mem_store
                push.{da2} push.10 mem_store
                push.{da3} push.11 mem_store
                push.{da4} push.12 mem_store
                push.0 push.13 mem_store
                push.0 push.14 mem_store
                push.0 push.15 mem_store
                push.0 push.16 mem_store
                push.0 push.17 mem_store
                push.0 push.18 mem_store
                push.0 push.19 mem_store
                push.0 push.20 mem_store
                push.{mh0} push.21 mem_store
                push.{mh1} push.22 mem_store
                push.{mh2} push.23 mem_store
                push.{mh3} push.24 mem_store
                push.{mh4} push.25 mem_store
                push.{mh5} push.26 mem_store
                push.{mh6} push.27 mem_store
                push.{mh7} push.28 mem_store
                push.0 push.29 mem_store
                push.0 push.30 mem_store
                push.0 push.31 mem_store
                push.0
                exec.leaf_utils::compute_leaf_value
                exec.sys::truncate_stack
            end
        "#,
        leaf_type_swapped = leaf_type_swapped,
        origin_network_swapped = origin_network_swapped,
        oa0 = origin_addr_felts[0],
        oa1 = origin_addr_felts[1],
        oa2 = origin_addr_felts[2],
        oa3 = origin_addr_felts[3],
        oa4 = origin_addr_felts[4],
        dest_network_swapped = dest_network_swapped,
        da0 = dest_addr_felts[0],
        da1 = dest_addr_felts[1],
        da2 = dest_addr_felts[2],
        da3 = dest_addr_felts[3],
        da4 = dest_addr_felts[4],
        mh0 = mh[0],
        mh1 = mh[1],
        mh2 = mh[2],
        mh3 = mh[3],
        mh4 = mh[4],
        mh5 = mh[5],
        mh6 = mh[6],
        mh7 = mh[7],
    );

    let agglayer_lib = agglayer_library();
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib)
        .unwrap()
        .assemble_program(&source)
        .unwrap();

    let exec_output = execute_program_with_default_host(program, None).await?;
    let computed: Vec<u32> =
        exec_output.stack[0..8].iter().map(|f| f.as_canonical_u64() as u32).collect();
    let expected: Vec<u32> =
        expected_felts.iter().map(|f: &Felt| f.as_canonical_u64() as u32).collect();

    assert_eq!(
        computed, expected,
        "MASM compute_leaf_value with leafType=1 should match Rust Keccak256"
    );

    Ok(())
}
