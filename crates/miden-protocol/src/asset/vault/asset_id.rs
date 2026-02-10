use crate::Felt;

/// The [`AssetId`] in an [`AssetVaultKey`](crate::asset::AssetVaultKey) distinguishes different
/// assets issued by the same faucet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}
