use alloc::vec::Vec;

use miden_core::Felt;
#[cfg(any(test, feature = "testing"))]
use miden_core::Word;
use miden_core::utils::bytes_to_packed_u32_elements;
use miden_protocol::utils::{HexParseError, hex_to_bytes};

// KECCAK256 OUTPUT
// ================================================================================================

/// Keccak256 output representation (32-byte hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keccak256Output([u8; 32]);

impl Keccak256Output {
    /// Creates a new Keccak256 output from a 32-byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a [`Keccak256Output`] from a hex string (with or without "0x" prefix).
    ///
    /// The hex string should represent 32 bytes (64 hex characters).
    pub fn from_hex(hex_str: &str) -> Result<Self, HexParseError> {
        let bytes: [u8; 32] = hex_to_bytes(hex_str)?;
        Ok(Self(bytes))
    }

    /// Returns the inner 32-byte array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the Keccak256 output to 8 Felt elements (32-byte value as 8 u32 values in
    /// little-endian)
    pub fn to_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.0)
    }

    /// Converts the Keccak256 output to two [`Word`]s: `[lo, hi]`.
    ///
    /// - `lo` contains the first 4 u32-packed felts (bytes 0..16).
    /// - `hi` contains the last  4 u32-packed felts (bytes 16..32).
    #[cfg(any(test, feature = "testing"))]
    pub fn to_words(&self) -> [Word; 2] {
        let elements = self.to_elements();
        let lo: [Felt; 4] = elements[0..4].try_into().expect("to_elements returns 8 felts");
        let hi: [Felt; 4] = elements[4..8].try_into().expect("to_elements returns 8 felts");
        [Word::new(lo), Word::new(hi)]
    }
}

impl From<[u8; 32]> for Keccak256Output {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}
