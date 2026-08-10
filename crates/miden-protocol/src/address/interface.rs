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
/// An interface encodes to a `u16`, but is guaranteed to take up at most 10 of its bits. This
/// constraint allows encoding the interface into an address efficiently, sharing the remaining
/// bits with the note tag length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum AddressInterface {
    /// The basic wallet interface.
    BasicWallet = Self::BASIC_WALLET,
}

impl AddressInterface {
    /// The number of bits an encoded interface occupies in an address' receiver profile.
    ///
    /// The remaining bits of that profile carry the note tag length, so a variant that does not
    /// fit into this budget would corrupt both fields.
    pub(crate) const ENCODED_BITS: u32 = 10;

    // Constants for internal use only.
    const BASIC_WALLET: u16 = 0;
}

// The encoder guards this budget with a `debug_assert`, which is compiled out in release builds,
// so the discriminants are checked here at compile time as well.
const _: () = assert!(
    AddressInterface::BASIC_WALLET < (1u16 << AddressInterface::ENCODED_BITS),
    "address interface discriminants must fit into ENCODED_BITS bits",
);

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
