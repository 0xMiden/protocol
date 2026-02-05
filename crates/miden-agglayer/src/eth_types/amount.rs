use core::fmt;

use miden_core::FieldElement;
use miden_protocol::Felt;
use miden_protocol::utils::hex_to_bytes;

// ================================================================================================
// ETHEREUM AMOUNT ERROR
// ================================================================================================

/// Error type for Ethereum amount conversions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthAmountError {
    /// The amount doesn't fit in the target type.
    Overflow,
    /// Invalid hex string length (expected 64 hex characters, optionally with "0x" prefix).
    InvalidHexLength,
    /// Invalid hex character.
    InvalidHexChar(char),
}

impl fmt::Display for EthAmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthAmountError::Overflow => {
                write!(f, "amount overflow: value doesn't fit in target type")
            },
            EthAmountError::InvalidHexLength => {
                write!(f, "invalid hex length: expected 64 hex characters")
            },
            EthAmountError::InvalidHexChar(c) => {
                write!(f, "invalid hex character: {}", c)
            },
        }
    }
}

// ================================================================================================
// ETHEREUM AMOUNT
// ================================================================================================

/// Represents an Ethereum uint256 amount as 8 u32 values.
///
/// This type provides a more typed representation of Ethereum amounts compared to raw `[u32; 8]`
/// arrays, while maintaining compatibility with the existing MASM processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAmount([u32; 8]);

impl EthAmount {
    /// Creates a new [`EthAmount`] from an array of 8 u32 values.
    ///
    /// The values are stored in big-endian limb order where `values[0]` contains
    /// the most significant 32 bits. Each limb encodes its 4 bytes in little-endian
    /// order so felts map directly to keccak bytes.
    pub const fn new(values: [u32; 8]) -> Self {
        Self(values)
    }

    /// Creates an [`EthAmount`] from a single u64 value.
    ///
    /// This is useful for smaller amounts that fit in a u64. The value is
    /// stored in the last two u32 slots with the remaining slots set to zero.
    pub const fn from_u64(value: u64) -> Self {
        let low = u32::from_le_bytes((value as u32).to_be_bytes());
        let high = u32::from_le_bytes(((value >> 32) as u32).to_be_bytes());
        let mut values = [0u32; 8];
        values[6] = high;
        values[7] = low;
        Self(values)
    }

    /// Creates an [`EthAmount`] from a single u32 value.
    ///
    /// This is useful for smaller amounts that fit in a u32. The value is
    /// stored in the last u32 slot with the remaining slots set to zero.
    pub const fn from_u32(value: u32) -> Self {
        let mut values = [0u32; 8];
        values[7] = u32::from_le_bytes(value.to_be_bytes());
        Self(values)
    }

    /// Creates an [`EthAmount`] from a 32-byte array in big-endian order.
    ///
    /// The bytes are interpreted as a 256-bit big-endian integer. Each 4-byte
    /// chunk is stored as a little-endian u32 so felts map directly to bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut values = [0u32; 8];
        for (i, chunk) in bytes.chunks(4).enumerate() {
            values[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        Self(values)
    }

    /// Creates an [`EthAmount`] from a hex string (with or without "0x" prefix).
    ///
    /// The hex string must represent exactly 32 bytes (64 hex characters).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string length is invalid or contains non-hex characters.
    pub fn from_hex(hex_str: &str) -> Result<Self, EthAmountError> {
        let bytes: [u8; 32] =
            hex_to_bytes(hex_str).map_err(|_| EthAmountError::InvalidHexLength)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Returns the raw array of 8 u32 values.
    pub const fn as_array(&self) -> &[u32; 8] {
        &self.0
    }

    /// Converts the amount into an array of 8 u32 values.
    pub const fn into_array(self) -> [u32; 8] {
        self.0
    }

    /// Returns true if the amount is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }

    /// Attempts to convert the amount to a u64.
    ///
    /// # Errors
    /// Returns [`EthAmountError::Overflow`] if the amount doesn't fit in a u64
    /// (i.e., if any of the upper 24 bytes are non-zero).
    pub fn try_to_u64(&self) -> Result<u64, EthAmountError> {
        let bytes = self.to_bytes_be();
        if bytes[..24].iter().any(|&b| b != 0) {
            Err(EthAmountError::Overflow)
        } else {
            Ok(u64::from_be_bytes(bytes[24..32].try_into().unwrap()))
        }
    }

    /// Attempts to convert the amount to a u32.
    ///
    /// # Errors
    /// Returns [`EthAmountError::Overflow`] if the amount doesn't fit in a u32
    /// (i.e., if any of the upper 28 bytes are non-zero).
    pub fn try_to_u32(&self) -> Result<u32, EthAmountError> {
        let bytes = self.to_bytes_be();
        if bytes[..28].iter().any(|&b| b != 0) {
            Err(EthAmountError::Overflow)
        } else {
            Ok(u32::from_be_bytes(bytes[28..32].try_into().unwrap()))
        }
    }

    /// Converts the amount to a vector of field elements for note storage.
    ///
    /// Each u32 value in the amount array is converted to a [`Felt`].
    pub fn to_elements(&self) -> [Felt; 8] {
        let mut result = [Felt::ZERO; 8];
        for (i, &value) in self.0.iter().enumerate() {
            result[i] = Felt::from(value);
        }
        result
    }

    /// Converts the amount to a 32-byte array in big-endian order.
    ///
    /// This produces the Solidity `uint256` representation where `bytes[0..4]`
    /// contains the most significant 32 bits.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, &value) in self.0.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}

impl From<[u32; 8]> for EthAmount {
    fn from(values: [u32; 8]) -> Self {
        Self(values)
    }
}

impl From<EthAmount> for [u32; 8] {
    fn from(amount: EthAmount) -> Self {
        amount.0
    }
}

impl From<u64> for EthAmount {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u32> for EthAmount {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl fmt::Display for EthAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // For display purposes, show as a hex string of the full 256-bit value
        write!(f, "0x")?;
        for byte in self.to_bytes_be() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
