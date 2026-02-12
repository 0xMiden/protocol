use core::fmt::{self, Display, Formatter};

use crate::errors::AddressError;

/// The account interface of an [`Address`](super::Address).
///
/// An interface specifies the set of procedures of an account, which determines which notes it is
/// able to receive and consume.
///
/// The enum is non-exhaustive so it can be extended in the future without it being a breaking
/// change. Users are expected to match on the variants that they are able to handle and ignore the
/// remaining ones.
///
/// ## Guarantees
///
/// An interface encodes to a `u16`, but is guaranteed to take up at most 11 of its bits. This
/// constraint allows encoding the interface into an address efficiently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum AddressInterface {
    /// The basic wallet interface.
    BasicWallet = Self::BASIC_WALLET,
}

impl AddressInterface {
    // Constants for internal use only.
    const BASIC_WALLET: u16 = 0;
}

impl TryFrom<u16> for AddressInterface {
    type Error = AddressError;

    /// Decodes an [`AddressInterface`] from its bytes representation.
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            Self::BASIC_WALLET => Ok(Self::BasicWallet),
            other => Err(AddressError::UnknownAddressInterface(other)),
        }
    }
}

impl Display for AddressInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BasicWallet => write!(f, "BasicWallet"),
        }
    }
}
