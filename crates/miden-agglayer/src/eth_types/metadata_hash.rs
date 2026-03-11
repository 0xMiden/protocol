use alloc::vec;
use alloc::vec::Vec;

use miden_core_lib::handlers::bytes_to_packed_u32_felts;
use miden_protocol::Felt;
use tiny_keccak::{Hasher, Keccak};

// ================================================================================================
// METADATA HASH
// ================================================================================================

/// Represents a Keccak256 metadata hash as 32 bytes.
///
/// This type provides a typed representation of metadata hashes for the agglayer bridge,
/// while maintaining compatibility with the existing MASM processing pipeline.
///
/// The metadata hash is `keccak256(abi.encode(name, symbol, decimals))` where the encoding
/// follows Solidity's `abi.encode` format for `(string, string, uint8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetadataHash([u8; 32]);

impl MetadataHash {
    /// Creates a new [`MetadataHash`] from a 32-byte array.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Computes the metadata hash from raw ABI-encoded metadata bytes.
    ///
    /// This computes `keccak256(metadata_bytes)`.
    pub fn from_abi_encoded(metadata_bytes: &[u8]) -> Self {
        let mut hasher = Keccak::v256();
        hasher.update(metadata_bytes);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        Self(output)
    }

    /// Computes the metadata hash from token information.
    ///
    /// This computes `keccak256(abi.encode(name, symbol, decimals))` matching the Solidity
    /// bridge's `getTokenMetadata` encoding.
    pub fn from_token_info(name: &str, symbol: &str, decimals: u8) -> Self {
        let encoded = encode_token_metadata(name, symbol, decimals);
        Self::from_abi_encoded(&encoded)
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

// ABI ENCODING
// ================================================================================================

/// ABI-encodes token metadata as `abi.encode(name, symbol, decimals)`.
///
/// This produces the same encoding as Solidity's `abi.encode(string, string, uint8)`:
/// - 3 x 32-byte words for offsets/value of each parameter
/// - 32-byte length + padded data for name string
/// - 32-byte length + padded data for symbol string
pub(crate) fn encode_token_metadata(name: &str, symbol: &str, decimals: u8) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let symbol_bytes = symbol.as_bytes();

    // ABI encoding uses 32-byte u256 for offsets and lengths. We only write the lower 2 bytes,
    // so enforce a reasonable limit. Token names/symbols are typically < 32 bytes.
    assert!(name_bytes.len() <= 1024, "token name too long for ABI encoding");
    assert!(symbol_bytes.len() <= 1024, "token symbol too long for ABI encoding");

    let name_padded_data_len = pad_to_32(name_bytes.len());
    let symbol_padded_data_len = pad_to_32(symbol_bytes.len());

    // The 3 head slots (offsets + decimals) take 3 * 32 = 96 bytes
    let name_offset: usize = 3 * 32; // 0x60
    let symbol_offset: usize = name_offset + 32 + name_padded_data_len;

    let total_len = symbol_offset + 32 + symbol_padded_data_len;
    let mut buf = vec![0u8; total_len];

    // Write offset to name (big-endian u256)
    buf[31] = name_offset as u8;
    buf[30] = (name_offset >> 8) as u8;

    // Write offset to symbol (big-endian u256)
    buf[63] = symbol_offset as u8;
    buf[62] = (symbol_offset >> 8) as u8;

    // Write decimals (big-endian u256, value in last byte)
    buf[95] = decimals;

    // Write name: length word + data
    let name_len_offset = name_offset;
    buf[name_len_offset + 31] = name_bytes.len() as u8;
    buf[name_len_offset + 30] = (name_bytes.len() >> 8) as u8;
    buf[name_len_offset + 32..name_len_offset + 32 + name_bytes.len()].copy_from_slice(name_bytes);

    // Write symbol: length word + data
    let symbol_len_offset = symbol_offset;
    buf[symbol_len_offset + 31] = symbol_bytes.len() as u8;
    buf[symbol_len_offset + 30] = (symbol_bytes.len() >> 8) as u8;
    buf[symbol_len_offset + 32..symbol_len_offset + 32 + symbol_bytes.len()]
        .copy_from_slice(symbol_bytes);

    buf
}

/// Rounds up to the nearest multiple of 32.
fn pad_to_32(len: usize) -> usize {
    (len + 31) & !31
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_token_metadata_matches_solidity() {
        // From solidity-compat/test-vectors/claim_asset_vectors_local_tx.json:
        // Token: "Test Token", symbol: "TEST", decimals: 18
        // metadata_hash: 0x4d0d9fb7f9ab2f012da088dc1c228173723db7e09147fe4fea2657849d580161
        let expected_hash =
            hex_to_bytes32("4d0d9fb7f9ab2f012da088dc1c228173723db7e09147fe4fea2657849d580161");

        let hash = MetadataHash::from_token_info("Test Token", "TEST", 18);
        assert_eq!(hash.as_bytes(), &expected_hash);
    }

    #[test]
    fn test_encode_token_metadata_format() {
        let encoded = encode_token_metadata("Test Token", "TEST", 18);

        // Verify the ABI encoding structure:
        // Offset to name = 0x60 (96)
        assert_eq!(encoded[31], 0x60);
        // Offset to symbol = 0x60 + 0x20 (name length) + 0x20 (name data padded) = 0xa0
        assert_eq!(encoded[63], 0xa0);
        // Decimals = 18
        assert_eq!(encoded[95], 18);
        // Name length = 10 ("Test Token")
        assert_eq!(encoded[96 + 31], 10);
        // Name data starts at 96 + 32 = 128
        assert_eq!(&encoded[128..138], b"Test Token");
    }

    #[test]
    fn test_from_abi_encoded_matches_from_token_info() {
        let encoded = encode_token_metadata("Test Token", "TEST", 18);
        let hash_from_encoded = MetadataHash::from_abi_encoded(&encoded);
        let hash_from_info = MetadataHash::from_token_info("Test Token", "TEST", 18);
        assert_eq!(hash_from_encoded, hash_from_info);
    }

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }
}
