use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use miden_protocol::Felt;
use miden_protocol::account::AccountId;

use super::eth_address_format::{AddressConversionError, EthAddressFormat};

// ================================================================================================
// ETH ACCOUNT ID FORMAT
// ================================================================================================

/// Represents a Miden [`AccountId`] encoded in the 20-byte Ethereum address format.
///
/// This is a newtype around [`EthAddressFormat`] that adds Miden-specific conversion logic.
/// In the bridge-in flow, the 20-byte Ethereum address format encodes a Miden [`AccountId`]:
/// `0x00000000 || prefix(8) || suffix(8)`, where:
/// - prefix = bytes[4..12] as a big-endian u64
/// - suffix = bytes[12..20] as a big-endian u64
///
/// Note: prefix/suffix are *conceptual* 64-bit words; when converting to [`Felt`], we must ensure
/// `Felt::new(u64)` does not reduce mod p (checked explicitly in [`Self::to_account_id`]).
///
/// This type is used by integrators (Gateway, claim managers) to convert between Miden AccountIds
/// and the Ethereum address format when constructing CLAIM notes or calling the AggLayer Bridge
/// `bridgeAsset()` function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAccountIdFormat(EthAddressFormat);

impl EthAccountIdFormat {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`EthAccountIdFormat`] from a 20-byte array.
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(EthAddressFormat::new(bytes))
    }

    /// Creates an [`EthAccountIdFormat`] from a hex string (with or without "0x" prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the hex part is not exactly 40 characters.
    pub fn from_hex(hex_str: &str) -> Result<Self, AddressConversionError> {
        EthAddressFormat::from_hex(hex_str).map(Self)
    }

    /// Creates an [`EthAccountIdFormat`] from an [`AccountId`].
    ///
    /// This conversion is infallible: an [`AccountId`] is two felts, and `as_int()` yields `u64`
    /// words which we embed as `0x00000000 || prefix(8) || suffix(8)` (big-endian words).
    ///
    /// # Example
    /// ```ignore
    /// let address = EthAccountIdFormat::from_account_id(destination_account_id).into_inner().into_bytes();
    /// // then construct the CLAIM note with address...
    /// ```
    pub fn from_account_id(account_id: AccountId) -> Self {
        let felts: [Felt; 2] = account_id.into();

        let mut out = [0u8; 20];
        out[4..12].copy_from_slice(&felts[0].as_int().to_be_bytes());
        out[12..20].copy_from_slice(&felts[1].as_int().to_be_bytes());

        Self(EthAddressFormat::new(out))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the inner [`EthAddressFormat`].
    pub const fn as_eth_address(&self) -> &EthAddressFormat {
        &self.0
    }

    /// Consumes self and returns the inner [`EthAddressFormat`].
    pub const fn into_inner(self) -> EthAddressFormat {
        self.0
    }

    /// Returns the raw 20-byte array.
    pub const fn as_bytes(&self) -> &[u8; 20] {
        self.0.as_bytes()
    }

    /// Converts the address into a 20-byte array.
    pub const fn into_bytes(self) -> [u8; 20] {
        self.0.into_bytes()
    }

    /// Converts the address to a hex string (lowercase, 0x-prefixed).
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Converts the address into an array of 5 [`Felt`] values for Miden VM.
    ///
    /// See [`EthAddressFormat::to_elements`] for details on the encoding.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.0.to_elements()
    }

    // CONVERSION METHODS
    // --------------------------------------------------------------------------------------------

    /// Converts the destination address back to an [`AccountId`].
    ///
    /// This function is used internally during CLAIM note processing to extract
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
        let bytes = self.0.into_bytes();
        let (prefix, suffix) = bytes20_to_prefix_suffix(bytes)?;

        // Use `Felt::try_from(u64)` to avoid potential truncating conversion
        let prefix_felt =
            Felt::try_from(prefix).map_err(|_| AddressConversionError::FeltOutOfField)?;

        let suffix_felt =
            Felt::try_from(suffix).map_err(|_| AddressConversionError::FeltOutOfField)?;

        AccountId::try_from([prefix_felt, suffix_felt])
            .map_err(|_| AddressConversionError::InvalidAccountId)
    }
}

impl fmt::Display for EthAccountIdFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<EthAddressFormat> for EthAccountIdFormat {
    fn from(addr: EthAddressFormat) -> Self {
        Self(addr)
    }
}

impl From<EthAccountIdFormat> for EthAddressFormat {
    fn from(addr: EthAccountIdFormat) -> Self {
        addr.0
    }
}

impl From<[u8; 20]> for EthAccountIdFormat {
    fn from(bytes: [u8; 20]) -> Self {
        Self(EthAddressFormat::new(bytes))
    }
}

impl From<EthAccountIdFormat> for [u8; 20] {
    fn from(addr: EthAccountIdFormat) -> Self {
        addr.0.into()
    }
}

impl From<AccountId> for EthAccountIdFormat {
    fn from(account_id: AccountId) -> Self {
        EthAccountIdFormat::from_account_id(account_id)
    }
}

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

/// Convert `[u8; 20]` -> `(prefix, suffix)` by extracting the last 16 bytes.
/// Requires the first 4 bytes be zero.
/// Returns prefix and suffix values that match the MASM little-endian limb byte encoding:
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
