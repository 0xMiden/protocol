use alloc::string::{String, ToString};
use core::fmt;

use super::v0;
use crate::Felt;
use crate::account::account_id::AccountIdPrefixV0;
use crate::account::{AccountIdV0, AccountIdVersion, AccountStorageMode, AccountType};
use crate::errors::AccountIdError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ACCOUNT ID PREFIX
// ================================================================================================

/// The prefix of an [`AccountId`][id], i.e. its first field element.
///
/// See the [`AccountId`][id] documentation for details.
///
/// The serialization formats of [`AccountIdPrefix`] and [`AccountId`][id] are compatible. In
/// particular, a prefix can be deserialized from the serialized bytes of a full id.
///
/// [id]: crate::account::AccountId
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AccountIdPrefix {
    V0(AccountIdPrefixV0),
}

impl AccountIdPrefix {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The serialized size of an [`AccountIdPrefix`] in bytes.
    pub const SERIALIZED_SIZE: usize = 8;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new [`AccountIdPrefix`] from the given `prefix` without checking its
    /// validity.
    ///
    /// # Warning
    ///
    /// Validity of the ID prefix must be ensured by the caller. An invalid ID may lead to panics.
    ///
    /// # Panics
    ///
    /// Panics if the prefix does not contain a known account ID version.
    ///
    /// If `debug_assertions` are enabled (e.g. in debug mode), this function panics if the given
    /// felt is invalid according to the constraints in the [`AccountId`](crate::account::AccountId)
    /// documentation.
    pub fn new_unchecked(prefix: Felt) -> Self {
        // The prefix contains the metadata.
        // If we add more versions in the future, we may need to generalize this.
        match v0::extract_version(prefix.as_int())
            .expect("prefix should contain a valid account ID version")
        {
            AccountIdVersion::Version0 => Self::V0(AccountIdPrefixV0::new_unchecked(prefix)),
        }
    }

    /// Constructs a new [`AccountIdPrefix`] from the given `prefix` and checks its validity.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the ID constraints are not met. See the [constraints
    /// documentation](super::AccountId#constraints) for details.
    pub fn new(prefix: Felt) -> Result<Self, AccountIdError> {
        // The prefix contains the metadata.
        // If we add more versions in the future, we may need to generalize this.
        match v0::extract_version(prefix.as_int())? {
            AccountIdVersion::Version0 => AccountIdPrefixV0::new(prefix).map(Self::V0),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`Felt`] that represents this prefix.
    pub const fn as_felt(&self) -> Felt {
        match self {
            AccountIdPrefix::V0(id_prefix) => id_prefix.as_felt(),
        }
    }

    /// Returns the prefix as a [`u64`].
    pub const fn as_u64(&self) -> u64 {
        match self {
            AccountIdPrefix::V0(id_prefix) => id_prefix.as_u64(),
        }
    }

    /// Returns the type of this account ID.
    pub const fn account_type(&self) -> AccountType {
        match self {
            AccountIdPrefix::V0(id_prefix) => id_prefix.account_type(),
        }
    }

    /// Returns true if an account with this ID is a faucet (can issue assets).
    pub fn is_faucet(&self) -> bool {
        self.account_type().is_faucet()
    }

    /// Returns true if an account with this ID is a regular account.
    pub fn is_regular_account(&self) -> bool {
        self.account_type().is_regular_account()
    }

    /// Returns the storage mode of this account ID.
    pub fn storage_mode(&self) -> AccountStorageMode {
        match self {
            AccountIdPrefix::V0(id_prefix) => id_prefix.storage_mode(),
        }
    }

    /// Returns `true` if the full state of the account is public on chain, i.e. if the modes are
    /// [`AccountStorageMode::Public`] or [`AccountStorageMode::Network`], `false` otherwise.
    pub fn has_public_state(&self) -> bool {
        self.storage_mode().has_public_state()
    }

    /// Returns `true` if the storage mode is [`AccountStorageMode::Public`], `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.storage_mode().is_public()
    }

    /// Returns `true` if the storage mode is [`AccountStorageMode::Network`], `false` otherwise.
    pub fn is_network(&self) -> bool {
        self.storage_mode().is_network()
    }

    /// Returns `true` if self is a private account, `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.storage_mode().is_private()
    }

    /// Returns the version of this account ID.
    pub fn version(&self) -> AccountIdVersion {
        match self {
            AccountIdPrefix::V0(_) => AccountIdVersion::Version0,
        }
    }

    /// Returns the prefix as a big-endian, hex-encoded string.
    pub fn to_hex(self) -> String {
        match self {
            AccountIdPrefix::V0(id_prefix) => id_prefix.to_hex(),
        }
    }

    /// Returns `felt` with the fungible bit set to zero. The version must be passed as the location
    /// of the fungible bit may depend on the underlying account ID version.
    pub(crate) fn clear_fungible_bit(version: AccountIdVersion, felt: Felt) -> Felt {
        match version {
            AccountIdVersion::Version0 => {
                // Set the fungible bit to zero by taking the bitwise `and` of the felt with the
                // inverted is_faucet mask.
                let clear_fungible_bit_mask = !AccountIdV0::IS_FAUCET_MASK;
                Felt::try_from(felt.as_int() & clear_fungible_bit_mask)
                    .expect("felt should still be valid as we cleared a bit and did not set any")
            },
        }
    }
}

// CONVERSIONS FROM ACCOUNT ID PREFIX
// ================================================================================================

impl From<AccountIdPrefixV0> for AccountIdPrefix {
    fn from(id: AccountIdPrefixV0) -> Self {
        Self::V0(id)
    }
}

impl From<AccountIdPrefix> for Felt {
    fn from(id: AccountIdPrefix) -> Self {
        match id {
            AccountIdPrefix::V0(id_prefix) => id_prefix.into(),
        }
    }
}

impl From<AccountIdPrefix> for [u8; 8] {
    fn from(id: AccountIdPrefix) -> Self {
        match id {
            AccountIdPrefix::V0(id_prefix) => id_prefix.into(),
        }
    }
}

impl From<AccountIdPrefix> for u64 {
    fn from(id: AccountIdPrefix) -> Self {
        match id {
            AccountIdPrefix::V0(id_prefix) => id_prefix.into(),
        }
    }
}

// CONVERSIONS TO ACCOUNT ID PREFIX
// ================================================================================================

impl TryFrom<[u8; 8]> for AccountIdPrefix {
    type Error = AccountIdError;

    /// Tries to convert a byte array in big-endian order to an [`AccountIdPrefix`].
    ///
    /// # Errors
    ///
    /// Returns an error if any of the ID constraints are not met. See the [constraints
    /// documentation](super::AccountId#constraints) for details.
    fn try_from(value: [u8; 8]) -> Result<Self, Self::Error> {
        // The least significant byte of the ID prefix contains the metadata.
        let metadata_byte = value[7];
        // We only have one supported version for now, so we use the extractor from that version.
        // If we add more versions in the future, we may need to generalize this.
        let version = v0::extract_version(metadata_byte as u64)?;

        match version {
            AccountIdVersion::Version0 => AccountIdPrefixV0::try_from(value).map(Self::V0),
        }
    }
}

impl TryFrom<u64> for AccountIdPrefix {
    type Error = AccountIdError;

    /// Tries to convert a `u64` into an [`AccountIdPrefix`].
    ///
    /// # Errors
    ///
    /// Returns an error if any of the ID constraints are not met. See the [constraints
    /// documentation](super::AccountId#constraints) for details.
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let element = Felt::try_from(value.to_le_bytes().as_slice())
            .map_err(AccountIdError::AccountIdInvalidPrefixFieldElement)?;
        Self::new(element)
    }
}

impl TryFrom<Felt> for AccountIdPrefix {
    type Error = AccountIdError;

    /// Returns an [`AccountIdPrefix`] instantiated with the provided field element.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the ID constraints are not met. See the [constraints
    /// documentation](super::AccountId#constraints) for details.
    fn try_from(element: Felt) -> Result<Self, Self::Error> {
        Self::new(element)
    }
}

// COMMON TRAIT IMPLS
// ================================================================================================

impl PartialOrd for AccountIdPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AccountIdPrefix {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        u64::from(*self).cmp(&u64::from(*other))
    }
}

impl fmt::Display for AccountIdPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountIdPrefix {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            AccountIdPrefix::V0(id_prefix) => id_prefix.write_into(target),
        }
    }

    fn get_size_hint(&self) -> usize {
        match self {
            AccountIdPrefix::V0(id_prefix) => id_prefix.get_size_hint(),
        }
    }
}

impl Deserializable for AccountIdPrefix {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        <[u8; 8]>::read_from(source)?
            .try_into()
            .map_err(|err: AccountIdError| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountIdV0;

    #[test]
    fn account_id_prefix_construction() {
        // Use the highest possible input to check if the constructed id is a valid Felt in that
        // scenario.
        // Use the lowest possible input to check whether the constructor produces valid IDs with
        // all-zeroes input.
        for input in [[0xff; 15], [0; 15]] {
            for account_type in [
                AccountType::FungibleFaucet,
                AccountType::NonFungibleFaucet,
                AccountType::RegularAccountImmutableCode,
                AccountType::RegularAccountUpdatableCode,
            ] {
                for storage_mode in [AccountStorageMode::Private, AccountStorageMode::Public] {
                    let id = AccountIdV0::dummy(input, account_type, storage_mode);
                    let prefix = id.prefix();
                    assert_eq!(prefix.account_type(), account_type);
                    assert_eq!(prefix.storage_mode(), storage_mode);
                    assert_eq!(prefix.version(), AccountIdVersion::Version0);

                    // Do a serialization roundtrip to ensure validity.
                    let serialized_prefix = prefix.to_bytes();
                    AccountIdPrefix::read_from_bytes(&serialized_prefix).unwrap();
                    assert_eq!(serialized_prefix.len(), AccountIdPrefix::SERIALIZED_SIZE);
                }
            }
        }
    }
}
