use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use crate::errors::AccountIdError;

// ACCOUNT STORAGE MODE
// ================================================================================================

/// Describes where the state of the account is stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AccountStorageMode {
    #[default]
    /// The account's state is stored off-chain, and only a commitment to it is stored on-chain.
    Private = Self::PRIVATE,

    /// The account's full state is stored on-chain.
    Public = Self::PUBLIC,
}

impl AccountStorageMode {
    pub(crate) const PRIVATE: u8 = 0;
    pub(crate) const PUBLIC: u8 = 1;

    /// Returns the storage mode encoded to a 1-bit flag, where private is 0 and public is 1.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` if the storage mode is [`Self::Public`], `false` otherwise.
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Returns `true` if the storage mode is [`Self::Private`], `false` otherwise.
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }
}

impl fmt::Display for AccountStorageMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountStorageMode::Private => write!(f, "private"),
            AccountStorageMode::Public => write!(f, "public"),
        }
    }
}

impl TryFrom<&str> for AccountStorageMode {
    type Error = AccountIdError;

    fn try_from(value: &str) -> Result<Self, AccountIdError> {
        match value.to_lowercase().as_str() {
            "private" => Ok(AccountStorageMode::Private),
            "public" => Ok(AccountStorageMode::Public),
            _ => Err(AccountIdError::UnknownAccountStorageMode(value.into())),
        }
    }
}

impl TryFrom<String> for AccountStorageMode {
    type Error = AccountIdError;

    fn try_from(value: String) -> Result<Self, AccountIdError> {
        AccountStorageMode::from_str(&value)
    }
}

impl FromStr for AccountStorageMode {
    type Err = AccountIdError;

    fn from_str(input: &str) -> Result<AccountStorageMode, AccountIdError> {
        AccountStorageMode::try_from(input)
    }
}

#[cfg(any(feature = "testing", test))]
impl rand::distr::Distribution<AccountStorageMode> for rand::distr::StandardUniform {
    /// Samples a uniformly random [`AccountStorageMode`] from the given `rng`.
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AccountStorageMode {
        match rng.random_range(0..2) {
            0 => AccountStorageMode::Private,
            1 => AccountStorageMode::Public,
            _ => unreachable!("gen_range should not produce higher values"),
        }
    }
}
