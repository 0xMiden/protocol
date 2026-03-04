use alloc::vec::Vec;

use miden_protocol::Felt;

// UTILITY FUNCTIONS
// ================================================================================================

/// Converts Felt u32 limbs to bytes using little-endian byte order.
pub fn felts_to_bytes(limbs: &[Felt]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(limbs.len() * 4);
    for limb in limbs.iter() {
        let u32_value = limb.as_canonical_u64() as u32;
        let limb_bytes = u32_value.to_le_bytes();
        bytes.extend_from_slice(&limb_bytes);
    }
    bytes
}
