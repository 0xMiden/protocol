use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use crate::errors::AccountIdError;

// ACCOUNT TYPE
// ================================================================================================

/// The type of an account, which determines where the account state is stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AccountType {
    #[default]
    /// The account's state is stored off-chain, and only a commitment to it is stored on-chain.
    Private = Self::PRIVATE,

    /// The account's full state is stored on-chain.
    Public = Self::PUBLIC,
}

impl AccountType {
    pub(crate) const PRIVATE: u8 = 0;
    pub(crate) const PUBLIC: u8 = 1;

    /// Returns the account type encoded to a 1-bit flag, where private is 0 and public is 1.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` if the account type is [`Self::Public`], `false` otherwise.
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Returns `true` if the account type is [`Self::Private`], `false` otherwise.
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }
}

impl fmt::Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountType::Private => write!(f, "private"),
            AccountType::Public => write!(f, "public"),
        }
    }
}

impl TryFrom<&str> for AccountType {
    type Error = AccountIdError;

    fn try_from(value: &str) -> Result<Self, AccountIdError> {
        match value.to_lowercase().as_str() {
            "private" => Ok(AccountType::Private),
            "public" => Ok(AccountType::Public),
            _ => Err(AccountIdError::UnknownAccountType(value.into())),
        }
    }
}

impl TryFrom<String> for AccountType {
    type Error = AccountIdError;

    fn try_from(value: String) -> Result<Self, AccountIdError> {
        AccountType::from_str(&value)
    }
}

impl FromStr for AccountType {
    type Err = AccountIdError;

    fn from_str(input: &str) -> Result<AccountType, AccountIdError> {
        AccountType::try_from(input)
    }
}

#[cfg(any(feature = "testing", test))]
impl rand::distr::Distribution<AccountType> for rand::distr::StandardUniform {
    /// Samples a uniformly random [`AccountType`] from the given `rng`.
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AccountType {
        match rng.random_range(0..2) {
            0 => AccountType::Private,
            1 => AccountType::Public,
            _ => unreachable!("gen_range should not produce higher values"),
        }
    }
}
