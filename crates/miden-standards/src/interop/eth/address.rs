use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use miden_protocol::Felt;
use miden_protocol::utils::{
    HexParseError,
    bytes_to_hex_string,
    bytes_to_packed_u32_elements,
    hex_to_bytes,
};
use thiserror::Error;

// ================================================================================================
// ETHEREUM ADDRESS
// ================================================================================================

/// Represents a plain Ethereum address (20 bytes).
///
/// This is the base type for any 20-byte Ethereum address. It is used for:
/// - Origin token addresses (EVM token contract addresses)
/// - Destination addresses in the bridge-out flow (real Ethereum addresses)
/// - Any other context where a plain 20-byte Ethereum address is needed
///
/// # Representations used in this module
///
/// - Raw bytes: `[u8; 20]` in the conventional Ethereum big-endian byte order (`bytes[0]` is the
///   most-significant byte).
/// - MASM "address\[5\]" limbs: 5 x u32 limbs in *big-endian limb order* (each limb encodes its 4
///   bytes in little-endian order so felts map to keccak bytes directly):
///   - `address[0]` = bytes[0..4]   (most-significant 4 bytes)
///   - `address[1]` = bytes[4..8]
///   - `address[2]` = bytes[8..12]
///   - `address[3]` = bytes[12..16]
///   - `address[4]` = bytes[16..20] (least-significant 4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAddress([u8; 20]);

impl EthAddress {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`EthAddress`] from a 20-byte array.
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Creates an [`EthAddress`] from a hex string (with or without "0x" prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the hex part is not exactly 40 characters.
    pub fn from_hex(hex_str: &str) -> Result<Self, AddressConversionError> {
        let hex_part = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if hex_part.len() != 40 {
            return Err(AddressConversionError::InvalidHexLength);
        }

        let prefixed_hex = if hex_str.starts_with("0x") {
            hex_str.to_string()
        } else {
            format!("0x{}", hex_str)
        };

        let bytes: [u8; 20] = hex_to_bytes(&prefixed_hex)?;
        Ok(Self(bytes))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the underlying 20-byte array.
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Converts the address into a 20-byte array.
    pub const fn into_bytes(self) -> [u8; 20] {
        self.0
    }

    /// Converts the Ethereum address to a hex string (lowercase, 0x-prefixed).
    pub fn to_hex(&self) -> String {
        bytes_to_hex_string(self.0)
    }

    /// Converts the Ethereum address into an array of 5 [`Felt`] values for Miden VM.
    ///
    /// The returned order matches the Solidity ABI encoding convention (*big-endian limb order*):
    /// - `address[0]` = bytes[0..4]   (most-significant 4 bytes)
    /// - `address[1]` = bytes[4..8]
    /// - `address[2]` = bytes[8..12]
    /// - `address[3]` = bytes[12..16]
    /// - `address[4]` = bytes[16..20] (least-significant 4 bytes)
    ///
    /// Each limb is interpreted as a little-endian `u32` and stored in a [`Felt`].
    pub fn to_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.0)
    }
}

impl fmt::Display for EthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 20]> for EthAddress {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

/// Creates an [`EthAddress`] from a 32-byte (bytes32) value embedding a left-padded address.
///
/// In EVM ABI encoding, a bytes32-embedded address has bytes 0..12 zero and the 20-byte
/// address in bytes 12..32. This is the encoding used by bridges that carry an address in a
/// full bytes32 field.
///
/// # Errors
///
/// Returns an error if any of the leading 12 padding bytes are non-zero.
impl TryFrom<[u8; 32]> for EthAddress {
    type Error = AddressConversionError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        if bytes[0..12] != [0; 12] {
            return Err(AddressConversionError::NonZeroBytes32Padding);
        }

        let addr: [u8; 20] = bytes[12..32].try_into().expect("slice is exactly 20 bytes");
        Ok(Self(addr))
    }
}

impl From<EthAddress> for [u8; 20] {
    fn from(addr: EthAddress) -> Self {
        addr.0
    }
}

// ================================================================================================
// ADDRESS CONVERSION ERROR
// ================================================================================================

/// Error type for Ethereum address conversions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddressConversionError {
    /// The address word has non-zero padding.
    #[error("non-zero word padding")]
    NonZeroWordPadding,
    /// The address has a non-zero 4-byte prefix.
    #[error("address has non-zero 4-byte prefix")]
    NonZeroBytePrefix,
    /// A bytes32-embedded address has non-zero leading padding bytes.
    #[error("leading 12 bytes must be zero for a bytes32-embedded address")]
    NonZeroBytes32Padding,
    /// The hex string has an unexpected length.
    #[error("invalid hex length (expected 40 hex chars)")]
    InvalidHexLength,
    /// The hex string contains an invalid character.
    #[error("invalid hex character: {0}")]
    InvalidHexChar(char),
    /// The hex string could not be parsed.
    #[error("hex parse error")]
    HexParseError,
    /// A packed 8-byte value does not fit in the field.
    #[error("packed 8-byte value does not fit in the field")]
    FeltOutOfField,
    /// The decoded value is not a valid AccountId.
    #[error("invalid AccountId")]
    InvalidAccountId,
}

impl From<HexParseError> for AddressConversionError {
    fn from(_err: HexParseError) -> Self {
        AddressConversionError::HexParseError
    }
}
