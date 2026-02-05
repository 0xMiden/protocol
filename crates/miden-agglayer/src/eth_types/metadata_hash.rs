use alloc::vec::Vec;

use miden_core_lib::handlers::bytes_to_packed_u32_felts;
use miden_protocol::Felt;

// ================================================================================================
// METADATA HASH
// ================================================================================================

/// Represents a Keccak256 metadata hash as 32 bytes.
///
/// This type provides a typed representation of metadata hashes for the agglayer bridge,
/// while maintaining compatibility with the existing MASM processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetadataHash([u8; 32]);

impl MetadataHash {
    /// Creates a new [`MetadataHash`] from a 32-byte array.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the metadata hash to 8 Felt elements for MASM processing.
    ///
    /// Each 4-byte chunk is converted to a u32 using little-endian byte order.
    pub fn to_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_felts(&self.0)
    }
}
