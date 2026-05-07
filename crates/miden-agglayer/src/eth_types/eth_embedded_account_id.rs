use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use miden_protocol::Felt;
use miden_protocol::account::AccountId;

use super::eth_address::{AddressConversionError, EthAddress};

// ================================================================================================
// ETH EMBEDDED ACCOUNT ID
// ================================================================================================

/// Represents a Miden [`AccountId`] that can be encoded in the 20-byte Ethereum address format.
///
/// This type wraps an [`AccountId`] and provides conversions to/from the Ethereum address
/// encoding used in the bridge-in flow. In this encoding, the 20-byte Ethereum address format
/// stores a Miden [`AccountId`] as: `0x00000000 || prefix(8) || suffix(8)`, where:
/// - prefix = bytes[4..12] as a big-endian u64
/// - suffix = bytes[12..20] as a big-endian u64
///
/// Note: prefix/suffix are *conceptual* 64-bit words; when converting to [`Felt`], we must ensure
/// `Felt::new(u64)` does not reduce mod p (checked explicitly in [`Self::try_from_eth_address`]).
///
/// This type is used by integrators (Gateway, claim managers) to convert between Miden AccountIds
/// and the Ethereum address format when constructing CLAIM notes or calling the AggLayer Bridge
/// `bridgeAsset()` function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthEmbeddedAccountId(AccountId);

impl EthEmbeddedAccountId {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an [`EthEmbeddedAccountId`] from a 20-byte array.
    ///
    /// The bytes are interpreted as an Ethereum-encoded Miden [`AccountId`] (big-endian):
    /// `0x00000000 || prefix(8) || suffix(8)`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the first 4 bytes (i.e., the most significant bytes) are not zero,
    /// - packing the 8-byte prefix/suffix into [`Felt`] would reduce mod p,
    /// - or the resulting felts do not form a valid [`AccountId`].
    pub fn new(bytes: [u8; 20]) -> Result<Self, AddressConversionError> {
        Self::try_from_eth_address(EthAddress::new(bytes))
    }

    /// Creates an [`EthEmbeddedAccountId`] from a hex string (with or without "0x" prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid, the hex part is not exactly 40 characters,
    /// or the decoded bytes do not represent a valid embedded [`AccountId`].
    pub fn from_hex(hex_str: &str) -> Result<Self, AddressConversionError> {
        let addr = EthAddress::from_hex(hex_str)?;
        Self::try_from_eth_address(addr)
    }

    /// Creates an [`EthEmbeddedAccountId`] from an [`AccountId`].
    ///
    /// This conversion is infallible: an [`AccountId`] is always valid.
    ///
    /// # Example
    /// ```ignore
    /// let embedded = EthEmbeddedAccountId::from_account_id(destination_account_id);
    /// let address_bytes = embedded.to_eth_address().into_bytes();
    /// // then construct the CLAIM note with address_bytes...
    /// ```
    pub const fn from_account_id(account_id: AccountId) -> Self {
        Self(account_id)
    }

    /// Creates an [`EthEmbeddedAccountId`] from an [`EthAddress`].
    ///
    /// Validates that the address contains a properly encoded Miden [`AccountId`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the first 4 bytes are not zero (not in the embedded AccountId format),
    /// - packing the 8-byte prefix/suffix into [`Felt`] would reduce mod p,
    /// - or the resulting felts do not form a valid [`AccountId`].
    pub fn try_from_eth_address(addr: EthAddress) -> Result<Self, AddressConversionError> {
        let bytes = addr.into_bytes();
        let (prefix, suffix) = bytes20_to_prefix_suffix(bytes)?;

        let prefix_felt =
            Felt::try_from(prefix).map_err(|_| AddressConversionError::FeltOutOfField)?;

        let suffix_felt =
            Felt::try_from(suffix).map_err(|_| AddressConversionError::FeltOutOfField)?;

        let account_id = AccountId::try_from_elements(suffix_felt, prefix_felt)
            .map_err(|_| AddressConversionError::InvalidAccountId)?;

        Ok(Self(account_id))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the inner [`AccountId`].
    pub const fn to_account_id(&self) -> &AccountId {
        &self.0
    }

    /// Consumes self and returns the inner [`AccountId`].
    pub const fn into_account_id(self) -> AccountId {
        self.0
    }

    /// Converts the embedded account ID to an [`EthAddress`].
    ///
    /// The resulting 20-byte address has the format:
    /// `0x00000000 || prefix(8) || suffix(8)` (big-endian byte ordering).
    pub fn to_eth_address(&self) -> EthAddress {
        let mut out = [0u8; 20];
        out[4..12].copy_from_slice(&self.0.prefix().as_u64().to_be_bytes());
        out[12..20].copy_from_slice(&self.0.suffix().as_canonical_u64().to_be_bytes());

        EthAddress::new(out)
    }

    /// Returns the raw 20-byte Ethereum address encoding.
    pub fn to_bytes(&self) -> [u8; 20] {
        self.to_eth_address().into_bytes()
    }

    /// Converts the address to a hex string (lowercase, 0x-prefixed).
    pub fn to_hex(&self) -> String {
        self.to_eth_address().to_hex()
    }

    /// Converts the address into an array of 5 [`Felt`] values for Miden VM.
    ///
    /// See [`EthAddress::to_elements`] for details on the encoding.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.to_eth_address().to_elements()
    }
}

impl fmt::Display for EthEmbeddedAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_eth_address())
    }
}

impl TryFrom<EthAddress> for EthEmbeddedAccountId {
    type Error = AddressConversionError;

    fn try_from(addr: EthAddress) -> Result<Self, Self::Error> {
        Self::try_from_eth_address(addr)
    }
}

impl From<EthEmbeddedAccountId> for EthAddress {
    fn from(embedded: EthEmbeddedAccountId) -> Self {
        embedded.to_eth_address()
    }
}

impl TryFrom<[u8; 20]> for EthEmbeddedAccountId {
    type Error = AddressConversionError;

    fn try_from(bytes: [u8; 20]) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl From<EthEmbeddedAccountId> for [u8; 20] {
    fn from(embedded: EthEmbeddedAccountId) -> Self {
        embedded.to_bytes()
    }
}

impl From<AccountId> for EthEmbeddedAccountId {
    fn from(account_id: AccountId) -> Self {
        EthEmbeddedAccountId::from_account_id(account_id)
    }
}

impl From<EthEmbeddedAccountId> for AccountId {
    fn from(embedded: EthEmbeddedAccountId) -> Self {
        embedded.0
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
