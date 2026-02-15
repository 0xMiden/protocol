use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_core_lib::handlers::bytes_to_packed_u32_felts;
use miden_protocol::Felt;
use primitive_types::U256;

// ================================================================================================
// ETHEREUM AMOUNT
// ================================================================================================

/// Represents an Ethereum uint256 amount as 8 u32 values.
///
/// This type provides a more typed representation of Ethereum amounts compared to raw `[u32; 8]`
/// arrays, while maintaining compatibility with the existing MASM processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAmount([u8; 32]);

/// Error type for parsing an [`EthAmount`] from a decimal string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthAmountError(String);

impl EthAmount {
    /// Creates an [`EthAmount`] from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates an [`EthAmount`] from a decimal (uint) string.
    ///
    /// The string should contain only ASCII decimal digits (e.g. `"2000000000000000000"`).
    /// The value is stored as a 32-byte big-endian array, matching the Solidity uint256 layout.
    ///
    /// # Errors
    ///
    /// Returns [`EthAmountError`] if the string is empty, contains non-digit characters,
    /// or represents a value that overflows uint256.
    pub fn from_uint_str(s: &str) -> Result<Self, EthAmountError> {
        let value = U256::from_dec_str(s).map_err(|e| EthAmountError(e.to_string()))?;
        Ok(Self(value.to_big_endian()))
    }

    /// Converts the amount to a vector of field elements for note storage.
    ///
    /// Each u32 value in the amount array is converted to a [`Felt`].
    pub fn to_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_felts(&self.0)
    }

    /// Returns the raw 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
