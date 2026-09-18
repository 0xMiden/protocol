use crate::account::delta::AssetDeltaOperation;
use crate::account::{AccountVaultDelta, AssetDelta};
use crate::asset::Asset;

impl AccountVaultDelta {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates an [`AccountVaultDelta`] from the given iterators.
    ///
    /// # Panics
    ///
    /// Panics if the same asset is changed by more than one delta.
    pub fn from_iters(
        added_assets: impl IntoIterator<Item = Asset>,
        removed_assets: impl IntoIterator<Item = Asset>,
    ) -> Self {
        Self::new(
            added_assets
                .into_iter()
                .map(|added_asset| AssetDelta::new(AssetDeltaOperation::Add, added_asset))
                .chain(removed_assets.into_iter().map(|removed_asset| {
                    AssetDelta::new(AssetDeltaOperation::Remove, removed_asset)
                })),
        )
        .expect("duplicate entries passed to AccountVaultDelta::from_iters")
    }
}
