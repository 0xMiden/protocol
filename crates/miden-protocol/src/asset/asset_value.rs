use miden_crypto_derive::WordWrapper;

use crate::Word;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ASSET VALUE
// ================================================================================================

/// The value of an [`Asset`](crate::asset::Asset).
///
/// See its docs for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, WordWrapper)]
pub struct AssetValue(Word);

impl AssetValue {
    /// The serialized size of an asset value in bytes.
    pub const SERIALIZED_SIZE: usize = Word::SERIALIZED_SIZE;
}

impl From<AssetValue> for Word {
    fn from(value: AssetValue) -> Self {
        value.0
    }
}

impl core::fmt::Display for AssetValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.as_word()))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AssetValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_many(self.as_word());
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for AssetValue {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(AssetValue::from_raw(source.read()?))
    }
}
