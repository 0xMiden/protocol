use core::fmt;
use core::str::FromStr;

use crate::errors::AccountIdError;
use crate::utils::serde::{ByteReader, Deserializable, DeserializationError, Serializable};

// ACCOUNT TYPE
// ================================================================================================

pub(super) const FUNGIBLE_FAUCET: u8 = 0b10;
pub(super) const NON_FUNGIBLE_FAUCET: u8 = 0b11;
pub(super) const REGULAR_ACCOUNT_IMMUTABLE_CODE: u8 = 0b00;
pub(super) const REGULAR_ACCOUNT_UPDATABLE_CODE: u8 = 0b01;

/// Represents the different account types recognized by the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AccountType {
    FungibleFaucet = FUNGIBLE_FAUCET,
    NonFungibleFaucet = NON_FUNGIBLE_FAUCET,
    RegularAccountImmutableCode = REGULAR_ACCOUNT_IMMUTABLE_CODE,
    RegularAccountUpdatableCode = REGULAR_ACCOUNT_UPDATABLE_CODE,
}

impl AccountType {
    /// Returns `true` if the account is a faucet.
    pub fn is_faucet(&self) -> bool {
        matches!(self, Self::FungibleFaucet | Self::NonFungibleFaucet)
    }

    /// Returns `true` if the account is a regular account.
    pub fn is_regular_account(&self) -> bool {
        matches!(self, Self::RegularAccountImmutableCode | Self::RegularAccountUpdatableCode)
    }

    /// Returns the string representation of the [`AccountType`].
    fn as_str(&self) -> &'static str {
        match self {
            AccountType::FungibleFaucet => "FungibleFaucet",
            AccountType::NonFungibleFaucet => "NonFungibleFaucet",
            AccountType::RegularAccountImmutableCode => "RegularAccountImmutableCode",
            AccountType::RegularAccountUpdatableCode => "RegularAccountUpdatableCode",
        }
    }
}

#[cfg(any(feature = "testing", test))]
impl rand::distr::Distribution<AccountType> for rand::distr::StandardUniform {
    /// Samples a uniformly random [`AccountType`] from the given `rng`.
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AccountType {
        match rng.random_range(0..4) {
            0 => AccountType::RegularAccountImmutableCode,
            1 => AccountType::RegularAccountUpdatableCode,
            2 => AccountType::FungibleFaucet,
            3 => AccountType::NonFungibleFaucet,
            _ => unreachable!("gen_range should not produce higher values"),
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountType {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8);
    }
}

impl Deserializable for AccountType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num: u8 = source.read()?;
        match num {
            FUNGIBLE_FAUCET => Ok(AccountType::FungibleFaucet),
            NON_FUNGIBLE_FAUCET => Ok(AccountType::NonFungibleFaucet),
            REGULAR_ACCOUNT_IMMUTABLE_CODE => Ok(AccountType::RegularAccountImmutableCode),
            REGULAR_ACCOUNT_UPDATABLE_CODE => Ok(AccountType::RegularAccountUpdatableCode),
            _ => Err(DeserializationError::InvalidValue(format!("invalid account type: {num}"))),
        }
    }
}

impl FromStr for AccountType {
    type Err = AccountIdError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        match string {
            "FungibleFaucet" => Ok(AccountType::FungibleFaucet),
            "NonFungibleFaucet" => Ok(AccountType::NonFungibleFaucet),
            "RegularAccountImmutableCode" => Ok(AccountType::RegularAccountImmutableCode),
            "RegularAccountUpdatableCode" => Ok(AccountType::RegularAccountUpdatableCode),
            other => Err(AccountIdError::UnknownAccountType(other.into())),
        }
    }
}

impl core::fmt::Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl serde::Serialize for AccountType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl<'de> serde::Deserialize<'de> for AccountType {
    fn deserialize<D>(deserializer: D) -> Result<AccountType, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use alloc::string::String;

        use serde::de::Error;

        let string: String = serde::Deserialize::deserialize(deserializer)?;
        string.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The following test ensure there is a bit available to identify an account as a faucet or
    /// normal.
    #[test]
    fn test_account_id_faucet_bit() {
        const ACCOUNT_IS_FAUCET_MASK: u8 = 0b10;

        // faucets have a bit set
        assert_ne!((FUNGIBLE_FAUCET) & ACCOUNT_IS_FAUCET_MASK, 0);
        assert_ne!((NON_FUNGIBLE_FAUCET) & ACCOUNT_IS_FAUCET_MASK, 0);

        // normal accounts do not have the faucet bit set
        assert_eq!((REGULAR_ACCOUNT_IMMUTABLE_CODE) & ACCOUNT_IS_FAUCET_MASK, 0);
        assert_eq!((REGULAR_ACCOUNT_UPDATABLE_CODE) & ACCOUNT_IS_FAUCET_MASK, 0);
    }
}
