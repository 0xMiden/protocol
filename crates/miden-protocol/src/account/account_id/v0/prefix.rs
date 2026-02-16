use alloc::string::{String, ToString};
use core::fmt;
use core::hash::Hash;

use miden_core::Felt;
use miden_core::utils::{ByteReader, ByteWriter, Deserializable, Serializable};
use miden_processor::DeserializationError;

use crate::account::account_id::v0::{self, validate_prefix};
use crate::account::{AccountIdVersion, AccountStorageMode, AccountType};
use crate::errors::AccountIdError;

// ACCOUNT ID PREFIX VERSION 0
// ================================================================================================

/// The prefix of an [`AccountIdV0`](crate::account::AccountIdV0), i.e. its first field element.
///
/// See the [`AccountId`](crate::account::AccountId)'s documentation for details.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AccountIdPrefixV0 {
    prefix: Felt,
}

impl Hash for AccountIdPrefixV0 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.prefix.inner().hash(state);
    }
}

impl AccountIdPrefixV0 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The serialized size of an [`AccountIdPrefixV0`] in bytes.
    const SERIALIZED_SIZE: usize = 8;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// See [`AccountIdPrefix::new_unchecked`](crate::account::AccountIdPrefix::new_unchecked) for
    /// details.
    pub fn new_unchecked(prefix: Felt) -> Self {
        // Panic on invalid felts in debug mode.
        if cfg!(debug_assertions) {
            validate_prefix(prefix)
                .expect("AccountIdPrefix::new_unchecked called with invalid prefix");
        }

        AccountIdPrefixV0 { prefix }
    }

    /// See [`AccountIdPrefix::new`](crate::account::AccountIdPrefix::new) for details.
    pub fn new(prefix: Felt) -> Result<Self, AccountIdError> {
        validate_prefix(prefix)?;

        Ok(AccountIdPrefixV0 { prefix })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// See [`AccountIdPrefix::as_felt`](crate::account::AccountIdPrefix::as_felt) for details.
    pub const fn as_felt(&self) -> Felt {
        self.prefix
    }

    /// See [`AccountIdPrefix::as_u64`](crate::account::AccountIdPrefix::as_u64) for details.
    pub const fn as_u64(&self) -> u64 {
        self.prefix.as_int()
    }

    /// See [`AccountIdPrefix::account_type`](crate::account::AccountIdPrefix::account_type) for
    /// details.
    pub const fn account_type(&self) -> AccountType {
        v0::extract_type(self.prefix.as_int())
    }

    /// See [`AccountIdPrefix::is_faucet`](crate::account::AccountIdPrefix::is_faucet) for details.
    pub fn is_faucet(&self) -> bool {
        self.account_type().is_faucet()
    }

    /// See [`AccountIdPrefix::is_regular_account`](crate::account::AccountIdPrefix::is_regular_account) for
    /// details.
    pub fn is_regular_account(&self) -> bool {
        self.account_type().is_regular_account()
    }

    /// See [`AccountIdPrefix::storage_mode`](crate::account::AccountIdPrefix::storage_mode) for
    /// details.
    pub fn storage_mode(&self) -> AccountStorageMode {
        v0::extract_storage_mode(self.prefix.as_int())
            .expect("account ID prefix should have been constructed with a valid storage mode")
    }

    /// See [`AccountIdPrefix::is_public`](crate::account::AccountIdPrefix::is_public) for details.
    pub fn is_public(&self) -> bool {
        self.storage_mode().is_public()
    }

    /// See [`AccountIdPrefix::version`](crate::account::AccountIdPrefix::version) for details.
    pub fn version(&self) -> AccountIdVersion {
        v0::extract_version(self.prefix.as_int())
            .expect("account ID prefix should have been constructed with a valid version")
    }

    /// See [`AccountIdPrefix::to_hex`](crate::account::AccountIdPrefix::to_hex) for details.
    pub fn to_hex(self) -> String {
        format!("0x{:016x}", self.prefix.as_int())
    }
}

// CONVERSIONS FROM ACCOUNT ID PREFIX
// ================================================================================================

impl From<AccountIdPrefixV0> for Felt {
    fn from(id: AccountIdPrefixV0) -> Self {
        id.prefix
    }
}

impl From<AccountIdPrefixV0> for [u8; 8] {
    fn from(id: AccountIdPrefixV0) -> Self {
        let mut result = [0_u8; 8];
        result[..8].copy_from_slice(&id.prefix.as_int().to_be_bytes());
        result
    }
}

impl From<AccountIdPrefixV0> for u64 {
    fn from(id: AccountIdPrefixV0) -> Self {
        id.prefix.as_int()
    }
}

// CONVERSIONS TO ACCOUNT ID PREFIX
// ================================================================================================

impl TryFrom<[u8; 8]> for AccountIdPrefixV0 {
    type Error = AccountIdError;

    /// See [`TryFrom<[u8; 8]> for
    /// AccountIdPrefix`](crate::account::AccountIdPrefix#impl-TryFrom<%5Bu8;+8%
    /// 5D>-for-AccountIdPrefix) for details.
    fn try_from(mut value: [u8; 8]) -> Result<Self, Self::Error> {
        // Felt::try_from expects little-endian order.
        value.reverse();

        Felt::try_from(value.as_slice())
            .map_err(AccountIdError::AccountIdInvalidPrefixFieldElement)
            .and_then(Self::new)
    }
}

impl TryFrom<u64> for AccountIdPrefixV0 {
    type Error = AccountIdError;

    /// See [`TryFrom<u64> for
    /// AccountIdPrefix`](crate::account::AccountIdPrefix#impl-TryFrom<u64>-for-AccountIdPrefix)
    /// for details.
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let element = Felt::try_from(value.to_le_bytes().as_slice())
            .map_err(AccountIdError::AccountIdInvalidPrefixFieldElement)?;
        Self::new(element)
    }
}

impl TryFrom<Felt> for AccountIdPrefixV0 {
    type Error = AccountIdError;

    /// See [`TryFrom<Felt> for
    /// AccountIdPrefix`](crate::account::AccountIdPrefix#impl-TryFrom<Felt>-for-AccountIdPrefix)
    /// for details.
    fn try_from(element: Felt) -> Result<Self, Self::Error> {
        Self::new(element)
    }
}

// COMMON TRAIT IMPLS
// ================================================================================================

impl PartialOrd for AccountIdPrefixV0 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AccountIdPrefixV0 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.prefix.as_int().cmp(&other.prefix.as_int())
    }
}

impl fmt::Display for AccountIdPrefixV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountIdPrefixV0 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let bytes: [u8; 8] = (*self).into();
        bytes.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for AccountIdPrefixV0 {
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
    use crate::account::{AccountId, AccountIdPrefix};
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET, ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };

    #[test]
    fn test_account_id_prefix_conversion_roundtrip() {
        for (idx, account_id) in [
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
            ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PRIVATE_SENDER,
        ]
        .into_iter()
        .enumerate()
        {
            let full_id = AccountId::try_from(account_id).unwrap();
            let prefix = full_id.prefix();
            assert_eq!(
                prefix,
                AccountIdPrefix::read_from_bytes(&prefix.to_bytes()).unwrap(),
                "failed in {idx}"
            );
        }
    }
}
