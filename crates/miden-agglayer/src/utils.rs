use alloc::vec::Vec;

use miden_protocol::Felt;

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
