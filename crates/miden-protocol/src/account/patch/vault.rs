use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::asset::{Asset, AssetVaultKey};
use crate::{Felt, Word};

/// Describes the updates to an [`AssetVault`](crate::account::AssetVault) after a transaction.
///
/// The patch entries map an [`AssetVaultKey`] to the final [`Word`] value of the asset after the
/// update. If the asset was removed, the value is [`Word::empty`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountVaultPatch {
    entries: BTreeMap<AssetVaultKey, Word>,
}

impl AccountVaultPatch {
    /// Creates a new vault patch directly from its raw key/value entries.
    pub fn from_raw(entries: BTreeMap<AssetVaultKey, Word>) -> Self {
        Self { entries }
    }

    /// Inserts an asset into the patch, overwriting the previous value.
    pub fn insert_asset(&mut self, asset: Asset) {
        self.entries.insert(asset.vault_key(), asset.to_value_word());
    }

    /// Marks an asset as removed by inserting [`Word::empty`] into the patch.
    pub fn remove_asset(&mut self, asset_vault_key: AssetVaultKey) {
        self.entries.insert(asset_vault_key, Word::empty());
    }

    /// Returns a reference to the underlying map of the vault patch.
    pub fn as_map(&self) -> &BTreeMap<AssetVaultKey, Word> {
        &self.entries
    }

    /// Consumes self and returns the underlying map of the vault patch.
    pub fn into_map(self) -> BTreeMap<AssetVaultKey, Word> {
        self.entries
    }

    /// Returns an iterator over the asset key-value pairs contained in this patch, sorted by vault
    /// key.
    pub fn iter(&self) -> impl Iterator<Item = (&AssetVaultKey, &Word)> {
        self.entries.iter()
    }

    /// Returns `true` if this vault patch contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends the vault patch to the given `elements` from which the patch commitment will be
    /// computed.
    pub(super) fn append_patch_elements(&self, elements: &mut Vec<Felt>) {
        let domain_assets = Felt::from_u8(1);

        for (asset_vault_key, asset_value_or_empty_word) in self.entries.iter() {
            elements.extend_from_slice(asset_vault_key.to_word().as_elements());
            elements.extend_from_slice(asset_value_or_empty_word.as_elements());
        }

        let num_changed_assets = Felt::try_from(self.entries.len() as u64)
            .expect("number of assets should not exceed max representable felt");

        elements.extend_from_slice(&[domain_assets, num_changed_assets, Felt::ZERO, Felt::ZERO]);
        elements.extend_from_slice(Word::empty().as_elements());
    }
}
