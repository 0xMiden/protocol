use crate::errors::AssetError;

const CALLBACKS_DISABLED: u8 = 0;
const CALLBACKS_ENABLED: u8 = 1;

/// Whether callbacks are enabled for assets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetCallbacks {
    #[default]
    Disabled = CALLBACKS_DISABLED,

    Enabled = CALLBACKS_ENABLED,
}

impl AssetCallbacks {
    /// Encodes the callbacks setting as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for AssetCallbacks {
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
            _ => Err(AssetError::InvalidAssetCallbacks(value)),
        }
    }
}
