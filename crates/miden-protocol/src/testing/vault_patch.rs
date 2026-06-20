use miden_core::Word;

use crate::account::AccountVaultPatch;
use crate::asset::Asset;

impl AccountVaultPatch {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates an [`AccountVaultPatch`] that represents a vault update to the given assets.
    pub fn with_assets(entries: impl IntoIterator<Item = Asset>) -> Self {
        Self::new(
            entries
                .into_iter()
                .map(|asset| (asset.vault_key(), asset.to_value_word()))
                .collect(),
        )
        .expect("assets should be valid")
    }

    pub fn from_iters(
        added_assets: impl IntoIterator<Item = crate::asset::Asset>,
        removed_assets: impl IntoIterator<Item = crate::asset::Asset>,
    ) -> Self {
        Self::new(
            added_assets
                .into_iter()
                .map(|asset| (asset.vault_key(), asset.to_value_word()))
                .chain(removed_assets.into_iter().map(|asset| (asset.vault_key(), Word::empty())))
                .collect(),
        )
        .expect("assets should be valid")
    }
}
