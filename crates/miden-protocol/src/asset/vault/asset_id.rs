use core::fmt::Display;

use crate::{Felt, FieldElement};

/// The [`AssetId`] in an [`AssetVaultKey`](crate::asset::AssetVaultKey) distinguishes different
/// assets issued by the same faucet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AssetId {
    suffix: Felt,
    prefix: Felt,
}

impl AssetId {
    /// Constructs an asset ID from its parts.
    pub fn new(suffix: Felt, prefix: Felt) -> Self {
        Self { suffix, prefix }
    }

    /// Returns the suffix of the asset ID.
    pub fn suffix(&self) -> Felt {
        self.suffix
    }

    /// Returns the prefix of the asset ID.
    pub fn prefix(&self) -> Felt {
        self.prefix
    }

    /// Returns `true` if both prefix and suffix are zero, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.prefix == Felt::ZERO && self.suffix == Felt::ZERO
    }
}

impl Display for AssetId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "0x{:016x}{:016x}",
            self.prefix().as_int(),
            self.suffix().as_int()
        ))
    }
}
