use alloc::string::ToString;

use crate::errors::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// The flag in an [`AssetVaultKey`](super::AssetVaultKey) that indicates whether
/// [`AssetCallbacks`](super::AssetCallbacks) are enabled for this asset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetCallbackFlag {
    #[default]
    Disabled = Self::DISABLED,

    Enabled = Self::ENABLED,
}

impl AssetCallbackFlag {
    const DISABLED: u8 = 0;
    const ENABLED: u8 = 1;

    /// The serialized size of an [`AssetCallbackFlag`] in bytes.
    pub const SERIALIZED_SIZE: usize = core::mem::size_of::<AssetCallbackFlag>();

    /// Encodes the callbacks setting as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for AssetCallbackFlag {
    type Error = AssetError;

    /// Decodes a callbacks setting from a `u8`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a valid callbacks encoding.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::DISABLED => Ok(Self::Disabled),
            Self::ENABLED => Ok(Self::Enabled),
            _ => Err(AssetError::InvalidAssetCallbackFlag(value)),
        }
    }
}

impl Serializable for AssetCallbackFlag {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.as_u8());
    }

    fn get_size_hint(&self) -> usize {
        AssetCallbackFlag::SERIALIZED_SIZE
    }
}

impl Deserializable for AssetCallbackFlag {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::try_from(source.read_u8()?)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
