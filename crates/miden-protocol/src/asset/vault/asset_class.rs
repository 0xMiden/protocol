use core::fmt::Display;

use crate::Felt;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// The [`AssetClass`] in an [`AssetId`](crate::asset::AssetId) distinguishes different
/// assets issued by the same faucet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AssetClass {
    suffix: Felt,
    prefix: Felt,
}

impl AssetClass {
    /// The serialized size of an [`AssetClass`] in bytes.
    pub const SERIALIZED_SIZE: usize = 2 * core::mem::size_of::<u64>();

    /// Constructs an asset class from its parts.
    pub fn new(suffix: Felt, prefix: Felt) -> Self {
        Self { suffix, prefix }
    }

    /// Returns the suffix of the asset class.
    pub fn suffix(&self) -> Felt {
        self.suffix
    }

    /// Returns the prefix of the asset class.
    pub fn prefix(&self) -> Felt {
        self.prefix
    }

    /// Returns `true` if both prefix and suffix are zero, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.prefix == Felt::ZERO && self.suffix == Felt::ZERO
    }
}

impl Display for AssetClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "0x{:016x}{:016x}",
            self.prefix().as_canonical_u64(),
            self.suffix().as_canonical_u64()
        ))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AssetClass {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.suffix);
        target.write(self.prefix);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for AssetClass {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let suffix: Felt = source.read()?;
        let prefix: Felt = source.read()?;

        Ok(AssetClass::new(suffix, prefix))
    }
}
