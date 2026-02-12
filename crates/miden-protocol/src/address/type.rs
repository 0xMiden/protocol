use crate::errors::{AddressError, Bech32Error};

/// The type of an [`Address`](super::Address) in Miden.
///
/// The byte values of this address type should be chosen as a multiple of 8. That way, the first
/// character of the bech32 string after the `1` separator will be different for every address type.
/// This makes the type of the address conveniently human-readable.
///
/// For instance, [`AddressType::AccountId`] is chosen as 232 which is 0b1110_1000 in binary. Base32
/// encodes one character for every 5 bits and 0b11101 (= 29) translates to `a`. So, every account
/// ID address will start with `mm1a`.
///
/// See the table in the [bech32 spec](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32)
/// for a convenient overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum AddressType {
    AccountId = Self::ACCOUNT_ID,
}

impl AddressType {
    // Constants for internal use only.
    const ACCOUNT_ID: u8 = 232;
}

impl TryFrom<u8> for AddressType {
    type Error = AddressError;

    /// Decodes an [`AddressType`] from its byte representation.
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            Self::ACCOUNT_ID => Ok(Self::AccountId),
            other => Err(AddressError::Bech32DecodeError(Bech32Error::UnknownAddressType(other))),
        }
    }
}
