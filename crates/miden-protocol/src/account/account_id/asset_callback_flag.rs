// ASSET CALLBACK FLAG
// ================================================================================================

/// Indicates whether a faucet's assets trigger
/// [`AssetCallbacks`](crate::asset::AssetCallbacks) when they are added to an account or note.
///
/// The flag is an immutable property of the issuing faucet's [`AccountId`](super::AccountId),
/// encoded as a single bit of the ID prefix and fixed at account creation. Because every asset
/// carries its faucet's ID prefix, the kernel can derive this capability from the asset alone
/// without reading the faucet's account state.
///
/// When [`Enabled`](Self::Enabled), the kernel dispatches the faucet's callbacks whenever one of
/// its assets is added to a vault or note. When [`Disabled`](Self::Disabled), callbacks are skipped
/// entirely and no foreign-account read is performed.
///
/// The flag only enables the dispatch. On dispatch, the kernel reads the callback's procedure root
/// from the faucet's storage and skips the invocation if the callback slot is absent or holds the
/// empty word, so [`Enabled`](Self::Enabled) means callbacks may be invoked for the faucet's
/// assets, not that the faucet has any.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetCallbackFlag {
    #[default]
    Disabled = Self::DISABLED,

    Enabled = Self::ENABLED,
}

impl AssetCallbackFlag {
    pub(crate) const DISABLED: u8 = 0;
    pub(crate) const ENABLED: u8 = 1;

    /// Encodes the flag as a `u8`, where [`Disabled`](Self::Disabled) is `0` and
    /// [`Enabled`](Self::Enabled) is `1`.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Returns `true` if the flag is [`Enabled`](Self::Enabled), `false` otherwise.
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl From<bool> for AssetCallbackFlag {
    /// Maps `true` to [`Enabled`](Self::Enabled) and `false` to [`Disabled`](Self::Disabled).
    fn from(enabled: bool) -> Self {
        if enabled { Self::Enabled } else { Self::Disabled }
    }
}
