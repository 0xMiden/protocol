extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_agglayer::agglayer_library;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core_lib::CoreLibrary;
use miden_core_lib::handlers::keccak256::KeccakPreimage;
use miden_crypto::FieldElement;
use miden_processor::AdviceInputs;
use miden_protocol::{Felt, Hasher, Word};

use super::test_utils::execute_program_with_default_host;

/// Convert bytes to field elements (u32 words packed into felts)
fn bytes_to_felts(data: &[u8]) -> Vec<Felt> {
    let mut felts = Vec::new();

    // Pad data to multiple of 4 bytes
    let mut padded_data = data.to_vec();
    while !padded_data.len().is_multiple_of(4) {
        padded_data.push(0);
    }

    // Convert to u32 words in little-endian format
    for chunk in padded_data.chunks(4) {
        let u32_value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        felts.push(Felt::new(u32_value as u64));
    }

    // pad to next multiple of 4 felts
    while felts.len() % 4 != 0 {
        felts.push(Felt::ZERO);
    }

    felts
}

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
    let input_felts = bytes_to_felts(&input_u8);
    assert_eq!(input_felts.len(), 32);

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
