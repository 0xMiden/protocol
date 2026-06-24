use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::asset::{Asset, AssetVaultKey};
use crate::errors::AssetError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
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
    /// Domain separator for assets in the account patch commitment.
    const DOMAIN: Felt = Felt::new_unchecked(3);

    /// Creates a new vault patch directly from its raw key/value entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided entries are not valid assets, unless the value is
    /// [`Word::empty`].
    pub fn new(entries: BTreeMap<AssetVaultKey, Word>) -> Result<Self, AssetError> {
        for (key, value) in entries.iter() {
            // If the asset was not removed (final value != Word::empty), ensure the provided entry
            // is a valid asset.
            if !value.is_empty() {
                Asset::from_key_value(*key, *value)?;
            }
        }

        Ok(Self { entries })
    }

    /// Inserts an asset into the patch, overwriting the previous value.
    pub fn insert_asset(&mut self, asset: Asset) {
        self.entries.insert(asset.vault_key(), asset.to_value_word());
    }

    /// Marks an asset as removed by inserting [`Word::empty`] into the patch.
    pub fn remove_asset(&mut self, asset_vault_key: AssetVaultKey) {
        self.entries.insert(asset_vault_key, Word::empty());
    }

    /// Returns the number of assets being patched.
    pub fn num_assets(&self) -> usize {
        self.entries.len()
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

    /// Merges another vault patch into this one. Entries from `other` overwrite any existing
    /// entries in `self` for the same [`AssetVaultKey`].
    pub fn merge(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    /// Appends the vault patch to the given `elements` from which the patch commitment will be
    /// computed.
    pub(super) fn append_patch_elements(&self, elements: &mut Vec<Felt>) {
        for (asset_vault_key, asset_value_or_empty_word) in self.entries.iter() {
            elements.extend_from_slice(asset_vault_key.to_word().as_elements());
            elements.extend_from_slice(asset_value_or_empty_word.as_elements());
        }

        let num_changed_assets = self.entries.len();
        if num_changed_assets != 0 {
            let num_changed_assets = Felt::try_from(num_changed_assets as u64)
                .expect("number of assets should not exceed max representable felt");

            elements.extend_from_slice(&[Self::DOMAIN, num_changed_assets, Felt::ZERO, Felt::ZERO]);
            elements.extend_from_slice(Word::empty().as_elements());
        }
    }

    /// Returns an iterator over the keys of assets that were removed (i.e. whose value is
    /// [`Word::empty`]).
    pub fn removed_asset_keys(&self) -> impl Iterator<Item = &AssetVaultKey> {
        self.entries
            .iter()
            .filter(|(_key, value)| value.is_empty())
            .map(|(key, _value)| key)
    }

    /// Returns an iterator over the assets that were added or updated (i.e. whose value is not
    /// [`Word::empty`]).
    pub fn updated_assets(&self) -> impl Iterator<Item = Asset> {
        self.entries
            .iter()
            .filter(|(_key, value)| !value.is_empty())
            .map(|(key, value)| {
                Asset::from_key_value(*key, *value).expect("patch should track valid assets")
            })
    }
}

impl Serializable for AccountVaultPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.removed_asset_keys().count());
        target.write_many(self.removed_asset_keys());

        target.write_usize(self.updated_assets().count());
        target.write_many(self.updated_assets());
    }

    fn get_size_hint(&self) -> usize {
        let removed_size = AssetVaultKey::SERIALIZED_SIZE * self.removed_asset_keys().count();
        let updated_size: usize = self.updated_assets().map(|asset| asset.get_size_hint()).sum();

        2 * 0usize.get_size_hint() + removed_size + updated_size
    }
}

impl Deserializable for AccountVaultPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_removed_assets = source.read_usize()?;
        let mut entries: BTreeMap<AssetVaultKey, Word> = source
            .read_many_iter::<AssetVaultKey>(num_removed_assets)?
            .map(|result| result.map(|key| (key, Word::empty())))
            .collect::<Result<_, _>>()?;

        let num_added_assets = source.read_usize()?;
        for result in source.read_many_iter::<Asset>(num_added_assets)? {
            let asset = result?;
            entries.insert(asset.vault_key(), asset.to_value_word());
        }

        Self::new(entries).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::{FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;

    #[test]
    fn account_vault_patch_serde() -> anyhow::Result<()> {
        let empty_patch = AccountVaultPatch::default();
        let serialized = empty_patch.to_bytes();
        let deserialized = AccountVaultPatch::read_from_bytes(&serialized)?;
        assert_eq!(empty_patch, deserialized);
        assert_eq!(empty_patch.get_size_hint(), serialized.len());

        let asset_0: Asset = FungibleAsset::mock(100);
        let asset_1: Asset =
            FungibleAsset::new(ACCOUNT_ID_PRIVATE_SENDER.try_into()?, 500_000)?.into();
        let asset_2: Asset = NonFungibleAsset::mock(&[10]);
        let asset_3: Asset = NonFungibleAsset::mock(&[20]);
        let patch = AccountVaultPatch::from_iters([asset_0, asset_1, asset_2], [asset_3]);

        let serialized = patch.to_bytes();
        let deserialized = AccountVaultPatch::read_from_bytes(&serialized)?;
        assert_eq!(deserialized, patch);
        assert_eq!(patch.get_size_hint(), serialized.len());

        Ok(())
    }
}
