use crate::errors::AssetError;

/// Describes whether an asset was added or removed in an
/// [`AccountVaultDelta`](crate::account::AccountVaultDelta).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetDeltaOperation {
    Add = Self::ADD,
    Remove = Self::REMOVE,
}

impl AssetDeltaOperation {
    // The encoding starts at 1 to leave 0 to encode a possible default `None` operation ("nothing
    // has changed").
    const ADD: u8 = 1;
    const REMOVE: u8 = 2;

    /// Encodes the delta operation as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for AssetDeltaOperation {
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
