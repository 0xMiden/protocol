use alloc::vec::Vec;

use alloy_sol_types::{SolValue, sol};
use miden_core::utils::bytes_to_packed_u32_elements;
use miden_crypto::hash::keccak::Keccak256;
use miden_protocol::Felt;

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
        let digest = Keccak256::hash(metadata_bytes);
        Self(<[u8; 32]>::from(digest))
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
        bytes_to_packed_u32_elements(&self.0)
    }
}

// ABI ENCODING
// ================================================================================================

sol! {
    struct SolTokenMetadata {
        string name;
        string symbol;
        uint8 decimals;
    }
}

/// ABI-encodes token metadata as `abi.encode(name, symbol, decimals)`.
///
/// This produces the same encoding as Solidity's `abi.encode(string, string, uint8)`.
pub(crate) fn encode_token_metadata(name: &str, symbol: &str, decimals: u8) -> Vec<u8> {
    SolTokenMetadata {
        name: name.into(),
        symbol: symbol.into(),
        decimals,
    }
    .abi_encode_params()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use std::path::Path;

    use miden_protocol::utils::hex_to_bytes;
    use serde::Deserialize;

    use super::*;

    /// Partial deserialization of claim_asset_vectors_local_tx.json
    #[derive(Deserialize)]
    struct ClaimAssetVectors {
        metadata: std::string::String,
        metadata_hash: std::string::String,
    }

    fn load_test_vectors() -> ClaimAssetVectors {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("solidity-compat/test-vectors/claim_asset_vectors_local_tx.json");
        let data = std::fs::read_to_string(path).expect("failed to read test vectors");
        serde_json::from_str(&data).expect("failed to parse test vectors")
    }

    #[test]
    fn test_metadata_hash_matches_solidity() {
        let vectors = load_test_vectors();
        let expected_metadata = hex_to_vec(&vectors.metadata[2..]);
        let expected_hash: [u8; 32] =
            hex_to_bytes(&vectors.metadata_hash).expect("valid metadata_hash hex");

        // The test vectors use: name="Test Token", symbol="TEST", decimals=18
        let encoded = encode_token_metadata("Test Token", "TEST", 18);
        assert_eq!(encoded, expected_metadata, "ABI encoding must match Solidity");

        let hash = MetadataHash::from_abi_encoded(&encoded);
        assert_eq!(hash.as_bytes(), &expected_hash, "keccak256 hash must match Solidity");

        let hash_from_info = MetadataHash::from_token_info("Test Token", "TEST", 18);
        assert_eq!(hash, hash_from_info, "from_abi_encoded and from_token_info must agree");
    }

    fn hex_to_vec(hex: &str) -> std::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
