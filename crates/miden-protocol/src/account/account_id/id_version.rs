use crate::errors::AccountIdError;

// ACCOUNT ID VERSION
// ================================================================================================

const VERSION_1_NUMBER: u8 = 1;

/// The version of an [`AccountId`](crate::account::AccountId).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccountIdVersion {
    Version1 = VERSION_1_NUMBER,
}

impl AccountIdVersion {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the version number.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for AccountIdVersion {
    type Error = AccountIdError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            VERSION_1_NUMBER => Ok(AccountIdVersion::Version1),
            other_version => Err(AccountIdError::UnknownAccountIdVersion(other_version)),
        }
    }
}

impl From<AccountIdVersion> for u8 {
    fn from(value: AccountIdVersion) -> Self {
        value.as_u8()
    }
}
