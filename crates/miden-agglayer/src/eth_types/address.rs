use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;

use miden_core::FieldElement;
use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::utils::{HexParseError, bytes_to_hex_string, hex_to_bytes};

// ================================================================================================
// ETHEREUM ADDRESS
// ================================================================================================

/// Represents an Ethereum address format (20 bytes).
///
/// # Representations used in this module
///
/// - Raw bytes: `[u8; 20]` in the conventional Ethereum big-endian byte order (`bytes[0]` is the
///   most-significant byte).
/// - MASM "address\[5\]" limbs: 5 x u32 limbs in *little-endian limb order*:
///   - addr0 = bytes[16..19] (least-significant 4 bytes)
///   - addr1 = bytes[12..15]
///   - addr2 = bytes[ 8..11]
///   - addr3 = bytes[ 4.. 7]
///   - addr4 = bytes[ 0.. 3] (most-significant 4 bytes)
/// - Embedded AccountId format: `0x00000000 || prefix(8) || suffix(8)`, where:
///   - prefix = (addr3 << 32) | addr2 = bytes[4..11] as a big-endian u64
///   - suffix = (addr1 << 32) | addr0 = bytes[12..19] as a big-endian u64
///
/// Note: prefix/suffix are *conceptual* 64-bit words; when converting to [`Felt`], we must ensure
/// `Felt::new(u64)` does not reduce mod p (checked explicitly in `to_account_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAddressFormat([u8; 20]);

impl EthAddressFormat {
    // EXTERNAL API - For integrators (Gateway, claim managers, etc.)
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`EthAddressFormat`] from a 20-byte array.
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Creates an [`EthAddressFormat`] from a hex string (with or without "0x" prefix).
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

    /// Creates an [`EthAddressFormat`] from an [`AccountId`].
    ///
    /// **External API**: This function is used by integrators (Gateway, claim managers) to convert
    /// Miden AccountIds into the Ethereum address format for constructing CLAIM notes or
    /// interfacing when calling the Agglayer Bridge function bridgeAsset().
    ///
    /// This conversion is infallible: an [`AccountId`] is two felts, and `as_int()` yields `u64`
    /// words which we embed as `0x00000000 || prefix(8) || suffix(8)` (big-endian words).
    ///
    /// # Example
    /// ```ignore
    /// let destination_address = EthAddressFormat::from_account_id(destination_account_id).into_bytes();
    /// // then construct the CLAIM note with destination_address...
    /// ```
    pub fn from_account_id(account_id: AccountId) -> Self {
        let felts: [Felt; 2] = account_id.into();

        let mut out = [0u8; 20];
        out[4..12].copy_from_slice(&felts[0].as_int().to_be_bytes());
        out[12..20].copy_from_slice(&felts[1].as_int().to_be_bytes());

        Self(out)
    }

    /// Returns the raw 20-byte array.
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

    // INTERNAL API - For CLAIM note processing
    // --------------------------------------------------------------------------------------------

    /// Converts the Ethereum address format into an array of 5 [`Felt`] values for MASM processing.
    ///
    /// **Internal API**: This function is used internally during CLAIM note processing to convert
    /// the address format into the MASM `address[5]` representation expected by the
    /// `to_account_id` procedure.
    ///
    /// The returned order matches the MASM `address\[5\]` convention (*little-endian limb order*):
    /// - addr0 = bytes[16..19] (least-significant 4 bytes)
    /// - addr1 = bytes[12..15]
    /// - addr2 = bytes[ 8..11]
    /// - addr3 = bytes[ 4.. 7]
    /// - addr4 = bytes[ 0.. 3] (most-significant 4 bytes)
    ///
    /// Each limb is interpreted as a big-endian `u32` and stored in a [`Felt`].
    pub fn to_elements(&self) -> [Felt; 5] {
        let mut result = [Felt::ZERO; 5];

        // i=0 -> bytes[16..20], i=4 -> bytes[0..4]
        for (felt, chunk) in result.iter_mut().zip(self.0.chunks(4).skip(1).rev()) {
            let value = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            // u32 values always fit in Felt, so this conversion is safe
            *felt = Felt::try_from(value as u64).expect("u32 value should always fit in Felt");
        }

        result
    }

    /// Converts the Ethereum address format back to an [`AccountId`].
    ///
    /// **Internal API**: This function is used internally during CLAIM note processing to extract
    /// the original AccountId from the Ethereum address format. It mirrors the functionality of
    /// the MASM `to_account_id` procedure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the first 4 bytes are not zero (not in the embedded AccountId format),
    /// - packing the 8-byte prefix/suffix into [`Felt`] would reduce mod p,
    /// - or the resulting felts do not form a valid [`AccountId`].
    pub fn to_account_id(&self) -> Result<AccountId, AddressConversionError> {
        let (prefix, suffix) = Self::bytes20_to_prefix_suffix(self.0)?;

        // Use `Felt::try_from(u64)` to avoid potential truncating conversion
        let prefix_felt =
            Felt::try_from(prefix).map_err(|_| AddressConversionError::FeltOutOfField)?;

        let suffix_felt =
            Felt::try_from(suffix).map_err(|_| AddressConversionError::FeltOutOfField)?;

        AccountId::try_from([prefix_felt, suffix_felt])
            .map_err(|_| AddressConversionError::InvalidAccountId)
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Convert `[u8; 20]` -> `(prefix, suffix)` by extracting the last 16 bytes.
    /// Requires the first 4 bytes be zero.
    /// Returns prefix and suffix values that match the MASM little-endian limb implementation:
    /// - prefix = bytes[4..12] as big-endian u64 = (addr3 << 32) | addr2
    /// - suffix = bytes[12..20] as big-endian u64 = (addr1 << 32) | addr0
    fn bytes20_to_prefix_suffix(bytes: [u8; 20]) -> Result<(u64, u64), AddressConversionError> {
        if bytes[0..4] != [0, 0, 0, 0] {
            return Err(AddressConversionError::NonZeroBytePrefix);
        }

        let prefix = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        let suffix = u64::from_be_bytes(bytes[12..20].try_into().unwrap());

        Ok((prefix, suffix))
    }
}

impl fmt::Display for EthAddressFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 20]> for EthAddressFormat {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl From<AccountId> for EthAddressFormat {
    fn from(account_id: AccountId) -> Self {
        EthAddressFormat::from_account_id(account_id)
    }
}

impl From<EthAddressFormat> for [u8; 20] {
    fn from(addr: EthAddressFormat) -> Self {
        addr.0
    }
}

// ================================================================================================
// ADDRESS CONVERSION ERROR
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressConversionError {
    NonZeroWordPadding,
    NonZeroBytePrefix,
    InvalidHexLength,
    InvalidHexChar(char),
    HexParseError,
    FeltOutOfField,
    InvalidAccountId,
}

impl fmt::Display for AddressConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressConversionError::NonZeroWordPadding => write!(f, "non-zero word padding"),
            AddressConversionError::NonZeroBytePrefix => {
                write!(f, "address has non-zero 4-byte prefix")
            },
            AddressConversionError::InvalidHexLength => {
                write!(f, "invalid hex length (expected 40 hex chars)")
            },
            AddressConversionError::InvalidHexChar(c) => write!(f, "invalid hex character: {}", c),
            AddressConversionError::HexParseError => write!(f, "hex parse error"),
            AddressConversionError::FeltOutOfField => {
                write!(f, "packed 64-bit word does not fit in the field")
            },
            AddressConversionError::InvalidAccountId => write!(f, "invalid AccountId"),
        }
    }
}

impl From<HexParseError> for AddressConversionError {
    fn from(_err: HexParseError) -> Self {
        AddressConversionError::HexParseError
    }
}
