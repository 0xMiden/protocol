extern crate alloc;

use alloc::vec::Vec;

use miden_core::FieldElement;
use miden_protocol::Felt;
use primitive_types::U256;

// UTILITY FUNCTIONS
// ================================================================================================

/// Converts a bytes32 value (32 bytes) into an array of 8 Felt values.
///
/// Note: These utility functions will eventually be replaced with similar functions from miden-vm.
pub fn bytes32_to_felts(bytes32: &[u8; 32]) -> [Felt; 8] {
    let mut result = [Felt::ZERO; 8];
    for (i, chunk) in bytes32.chunks(4).enumerate() {
        let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        result[i] = Felt::from(value);
    }
    result
}

/// Convert 8 Felt values (u32 limbs in little-endian order) to U256 bytes in little-endian format.
pub fn felts_to_u256_bytes(limbs: [Felt; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let u32_value = limb.as_int() as u32;
        let limb_bytes = u32_value.to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb_bytes);
    }
    bytes
}

/// Convert a U256 value to an array of 8 Felt values (u32 limbs in little-endian order).
///
/// The U256 is stored as 4 u64 words in little-endian order. We split each u64 into two u32 limbs.
pub fn u256_to_felts(value: U256) -> [Felt; 8] {
    let mut limbs = [Felt::ZERO; 8];
    for i in 0..4 {
        let word = value.0[i];
        limbs[i * 2] = Felt::new(word as u32 as u64); // Low 32 bits
        limbs[i * 2 + 1] = Felt::new((word >> 32) as u32 as u64); // High 32 bits
    }
    limbs
}

/// Convert an array of 8 Felt values (u32 limbs in little-endian order) to a U256 value.
pub fn felts_to_u256(felts: Vec<Felt>) -> U256 {
    assert_eq!(felts.len(), 8, "expected exactly 8 felts");
    let array: [Felt; 8] =
        [felts[0], felts[1], felts[2], felts[3], felts[4], felts[5], felts[6], felts[7]];
    let bytes = felts_to_u256_bytes(array);
    U256::from_little_endian(&bytes)
}
