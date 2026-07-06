use crate::errors::AccountError;

// STORAGE PATCH OPERATION
// ================================================================================================

/// Describes whether a storage slot was created, updated or removed in an
/// [`AccountStoragePatch`](crate::account::AccountStoragePatch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StoragePatchOperation {
    /// The slot was created.
    Create = Self::CREATE,

    /// An existing slot was updated.
    Update = Self::UPDATE,

    /// An existing slot was removed.
    Remove = Self::REMOVE,
}

impl StoragePatchOperation {
    const CREATE: u8 = 0;
    const UPDATE: u8 = 1;
    const REMOVE: u8 = 2;

    /// Encodes the patch operation as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Returns `true` if this is a [`StoragePatchOperation::Create`], `false` otherwise.
    pub const fn is_create(&self) -> bool {
        matches!(self, Self::Create)
    }

    /// Returns `true` if this is a [`StoragePatchOperation::Update`], `false` otherwise.
    pub const fn is_update(&self) -> bool {
        matches!(self, Self::Update)
    }

    /// Returns `true` if this is a [`StoragePatchOperation::Remove`], `false` otherwise.
    pub const fn is_remove(&self) -> bool {
        matches!(self, Self::Remove)
    }
}

impl TryFrom<u8> for StoragePatchOperation {
    type Error = AccountError;

    /// Decodes a patch operation from a `u8`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a valid patch operation.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::CREATE => Ok(Self::Create),
            Self::UPDATE => Ok(Self::Update),
            Self::REMOVE => Ok(Self::Remove),
            other => Err(AccountError::UnknownStoragePatchOperation(other)),
        }
    }
}
