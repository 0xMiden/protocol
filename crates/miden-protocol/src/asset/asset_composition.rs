use alloc::string::ToString;

use crate::errors::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// Indicates how an asset is composed (i.e. how its merge/split semantics are defined).
///
/// The composition is encoded in the metadata byte of an
/// [`AssetVaultKey`](super::AssetVaultKey) and determines how the asset is handled by the
/// asset vault, account delta and faucet logic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetComposition {
    /// Instances of the asset do not compose. In other words, they are non-fungible.
    #[default]
    None = Self::NONE,

    /// Instances of the asset compose according to the rules of the standard fungible asset.
    Fungible = Self::FUNGIBLE,

    /// Instances of the asset have a custom, faucet-defined composition logic.
    ///
    /// Exists for future use; currently effectively disabled.
    Custom = Self::CUSTOM,
}

impl AssetComposition {
    const NONE: u8 = 0;
    const FUNGIBLE: u8 = 1;
    const CUSTOM: u8 = 2;

    /// The serialized size of an [`AssetComposition`] in bytes.
    pub const SERIALIZED_SIZE: usize = core::mem::size_of::<AssetComposition>();

    /// Encodes the composition as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Returns true if the composition is [`AssetComposition::None`].
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns true if the composition is [`AssetComposition::Fungible`].
    pub const fn is_fungible(&self) -> bool {
        matches!(self, Self::Fungible)
    }

    /// Returns true if the composition is [`AssetComposition::Custom`].
    pub const fn is_custom(&self) -> bool {
        matches!(self, Self::Custom)
    }
}

impl TryFrom<u8> for AssetComposition {
    type Error = AssetError;

    /// Decodes a composition from a `u8`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a valid composition encoding.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::NONE => Ok(Self::None),
            Self::FUNGIBLE => Ok(Self::Fungible),
            Self::CUSTOM => Ok(Self::Custom),
            _ => Err(AssetError::UnknownAssetComposition(value)),
        }
    }
}

impl core::fmt::Display for AssetComposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let string = match self {
            AssetComposition::None => "none",
            AssetComposition::Fungible => "fungible",
            AssetComposition::Custom => "custom",
        };

        f.write_str(string)
    }
}

impl Serializable for AssetComposition {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.as_u8());
    }

    fn get_size_hint(&self) -> usize {
        AssetComposition::SERIALIZED_SIZE
    }
}

impl Deserializable for AssetComposition {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::try_from(source.read_u8()?)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
