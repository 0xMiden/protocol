use alloc::vec::Vec;

use miden_core::FieldElement;
use miden_protocol::Felt;
use primitive_types::U256;

// UTILITY FUNCTIONS
// ================================================================================================

/// Converts Felt u32 limbs to bytes using little-endian byte order.
/// TODO remove once we move to v0.21.0 which has `packed_u32_elements_to_bytes`
pub fn felts_to_bytes(limbs: &[Felt]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(limbs.len() * 4);
    for limb in limbs.iter() {
        let u32_value = limb.as_int() as u32;
        let limb_bytes = u32_value.to_le_bytes();
        bytes.extend_from_slice(&limb_bytes);
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
    let bytes = felts_to_bytes(&array);
    U256::from_little_endian(&bytes)
}
