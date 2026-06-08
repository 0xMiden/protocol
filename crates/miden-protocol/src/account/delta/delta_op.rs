use crate::errors::AssetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetDeltaOp {
    Add = Self::ADD,
    Remove = Self::REMOVE,
}

impl AssetDeltaOp {
    const ADD: u8 = 1;
    const REMOVE: u8 = 2;

    /// Encodes the delta operation as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for AssetDeltaOp {
    type Error = AssetError;

    /// Decodes a delta operation from a `u8`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a valid delta operation.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::ADD => Ok(Self::Add),
            Self::REMOVE => Ok(Self::Remove),
            _ => Err(AssetError::UnknownAssetDeltaOperation(value)),
        }
    }
}
