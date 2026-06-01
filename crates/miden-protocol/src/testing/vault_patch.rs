use crate::account::AccountVaultPatch;
use crate::asset::Asset;

impl AccountVaultPatch {
    // CONSTRUCTORS
    // ----------------------------------------------------------------------------------------

    /// Creates an [`AccountVaultPatch`] from the given iterators.
    pub fn with_assets(entries: impl IntoIterator<Item = Asset>) -> Self {
        Self::from_raw(
            entries
                .into_iter()
                .map(|asset| (asset.vault_key(), asset.to_value_word()))
                .collect(),
        )
    }
}
