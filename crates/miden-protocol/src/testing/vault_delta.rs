use crate::account::delta::AssetDeltaOperation;
use crate::account::{AccountVaultDelta, AssetDelta};
use crate::asset::Asset;

impl AccountVaultDelta {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates an [`AccountVaultDelta`] from the given iterators.
    pub fn from_iters(
        added_assets: impl IntoIterator<Item = Asset>,
        removed_assets: impl IntoIterator<Item = Asset>,
    ) -> Self {
        let mut delta = Self::default();

        for asset in added_assets {
            delta.insert(AssetDelta::new(AssetDeltaOperation::Add, asset));
        }

        for asset in removed_assets {
            delta.insert(AssetDelta::new(AssetDeltaOperation::Remove, asset));
        }

        delta
    }
}
