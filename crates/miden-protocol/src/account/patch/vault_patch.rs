use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::asset::{Asset, AssetVaultKey};
use crate::{Felt, Word};

/// Describes the updates to an [`AssetVault`](crate::account::AssetVault) after a transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountVaultPatch {
    entries: BTreeMap<AssetVaultKey, Word>,
}

impl AccountVaultPatch {
    /// Returns a new [`AccountVaultPatch`] containing the provided assets as the absolute values of
    /// changed vault entries.
    ///
    /// Duplicate vault keys in the iterator are silently deduplicated: only the last asset for a
    /// given key is retained.
    pub fn new(assets: impl IntoIterator<Item = Asset>) -> Self {
        Self {
            entries: assets
                .into_iter()
                .map(|asset| (asset.vault_key(), asset.to_value_word()))
                .collect(),
        }
    }

    /// Inserts an asset into the patch, overwriting the previous value.
    pub fn insert_asset(&mut self, asset: Asset) {
        self.entries.insert(asset.vault_key(), asset.to_value_word());
    }

    /// Returns an iterator over the assets contained in this patch, sorted by vault key.
    pub fn assets(&self) -> impl Iterator<Item = Asset> {
        self.entries.iter().map(|(key, value)| {
            Asset::from_key_value(*key, *value).expect("vault patch should store valid assets")
        })
    }

    /// Returns `true` if this vault patch contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends the vault patch to the given `elements` from which the patch commitment will be
    /// computed.
    pub(super) fn append_patch_elements(&self, elements: &mut Vec<Felt>) {
        let domain_assets = Felt::from_u8(1);

        for (asset_vault_key, asset_value) in self.entries.iter() {
            elements.extend_from_slice(asset_vault_key.to_word().as_elements());
            elements.extend_from_slice(asset_value.as_elements());
        }

        let num_changed_assets = Felt::try_from(self.entries.len() as u64)
            .expect("number of assets should not exceed max representable felt");

        elements.extend_from_slice(&[domain_assets, num_changed_assets, Felt::ZERO, Felt::ZERO]);
        elements.extend_from_slice(Word::empty().as_elements());
    }
}
