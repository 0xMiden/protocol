use alloc::string::ToString;

use crate::errors::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

const CALLBACKS_DISABLED: u8 = 0;
const CALLBACKS_ENABLED: u8 = 1;

/// Whether callbacks are enabled for assets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetCallbacksFlag {
    #[default]
    Disabled = CALLBACKS_DISABLED,

    Enabled = CALLBACKS_ENABLED,
}

impl AssetCallbacksFlag {
    /// The serialized size of an [`AssetCallbacksFlag`] in bytes.
    pub const SERIALIZED_SIZE: usize = core::mem::size_of::<AssetCallbacksFlag>();

    /// Encodes the callbacks setting as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for AssetCallbacksFlag {
    type Error = AssetError;

    /// Decodes a callbacks setting from a `u8`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a valid callbacks encoding.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            CALLBACKS_DISABLED => Ok(Self::Disabled),
            CALLBACKS_ENABLED => Ok(Self::Enabled),
            _ => Err(AssetError::InvalidAssetCallbacksFlag(value)),
        }
    }
}

impl Serializable for AssetCallbacksFlag {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.as_u8());
    }

    fn get_size_hint(&self) -> usize {
        AssetCallbacksFlag::SERIALIZED_SIZE
    }
}

impl Deserializable for AssetCallbacksFlag {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::try_from(source.read_u8()?)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
