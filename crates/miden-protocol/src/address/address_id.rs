use alloc::string::ToString;

use bech32::Bech32m;
use bech32::primitives::decode::CheckedHrpstring;
use miden_processor::DeserializationError;

use crate::account::AccountId;
use crate::address::{AddressType, NetworkId};
use crate::errors::{AddressError, Bech32Error};
use crate::utils::serde::{ByteWriter, Deserializable, Serializable};

/// The identifier of an [`Address`](super::Address).
///
/// See the address docs for more details.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressId {
    AccountId(AccountId),
}

impl AddressId {
    /// Returns the [`AddressType`] of this ID.
    pub fn address_type(&self) -> AddressType {
        match self {
            AddressId::AccountId(_) => AddressType::AccountId,
        }
    }

    /// Decodes a bech32 string into an identifier.
    pub(crate) fn decode(bech32_string: &str) -> Result<(NetworkId, Self), AddressError> {
        // We use CheckedHrpString with an explicit checksum algorithm so we don't allow the
        // `Bech32` or `NoChecksum` algorithms.
        let checked_string = CheckedHrpstring::new::<Bech32m>(bech32_string).map_err(|source| {
            // The CheckedHrpStringError does not implement core::error::Error, only
            // std::error::Error, so for now we convert it to a String. Even if it will
            // implement the trait in the future, we should include it as an opaque
            // error since the crate does not have a stable release yet.
            AddressError::Bech32DecodeError(Bech32Error::DecodeError(source.to_string().into()))
        })?;

        let hrp = checked_string.hrp();
        let network_id = NetworkId::from_hrp(hrp);

        let mut byte_iter = checked_string.byte_iter();

        // We only know the expected length once we know the address type, but to get the
        // address type, the length must be at least one.
        let address_byte = byte_iter.next().ok_or_else(|| {
            AddressError::Bech32DecodeError(Bech32Error::InvalidDataLength {
                expected: 1,
                actual: byte_iter.len(),
            })
        })?;

        let address_type = AddressType::try_from(address_byte)?;

        let identifier = match address_type {
            AddressType::AccountId => AccountId::from_bech32_byte_iter(byte_iter)
                .map_err(AddressError::AccountIdDecodeError)
                .map(AddressId::AccountId)?,
        };

        Ok((network_id, identifier))
    }
}

impl From<AccountId> for AddressId {
    fn from(id: AccountId) -> Self {
        Self::AccountId(id)
    }
}

impl Serializable for AddressId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.address_type() as u8);
        match self {
            AddressId::AccountId(id) => {
                id.write_into(target);
            },
        }
    }
}

impl Deserializable for AddressId {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let address_type: u8 = source.read_u8()?;
        let address_type = AddressType::try_from(address_type)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        match address_type {
            AddressType::AccountId => {
                let id: AccountId = source.read()?;
                Ok(AddressId::AccountId(id))
            },
        }
    }
}
