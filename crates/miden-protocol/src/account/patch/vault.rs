use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::AccountId;
use crate::asset::{Asset, AssetAmount, AssetCallbackFlag, AssetVaultKey, FungibleAsset};
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
    const DOMAIN: Felt = Felt::new_unchecked(4);

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
        for (asset_vault_key, asset_value_or_empty_word) in self.entries.iter() {
            elements.extend_from_slice(asset_vault_key.to_word().as_elements());
            elements.extend_from_slice(asset_value_or_empty_word.as_elements());
        }

        let num_changed_assets = Felt::try_from(self.entries.len() as u64)
            .expect("number of assets should not exceed max representable felt");

        elements.extend_from_slice(&[Self::DOMAIN, num_changed_assets, Felt::ZERO, Felt::ZERO]);
        elements.extend_from_slice(Word::empty().as_elements());
    }

    fn num_fungible_assets(&self) -> usize {
        self.entries
            .iter()
            .filter(|(key, _value)| key.composition().is_fungible())
            .count()
    }

    /// Returns an iterator over the parts of assets with `AssetComposition::Fungible` that are
    /// relevant for serialization.
    fn fungible_assets(&self) -> impl Iterator<Item = (AccountId, AssetCallbackFlag, AssetAmount)> {
        self.entries.iter().filter(|(key, _value)| key.composition().is_fungible()).map(
            |(key, value)| {
                // An empty word is also a valid encoding for a fungible asset, so we don't need
                // special handling.
                let asset = FungibleAsset::from_key_value(*key, *value)
                    .expect("patch should track valid assets");

                (asset.vault_key().faucet_id(), asset.vault_key().callback_flag(), asset.amount())
            },
        )
    }

    fn num_not_fungible_assets(&self) -> usize {
        self.not_fungible_assets().count()
    }

    /// Returns an iterator over all assets that do not have `AssetComposition::Fungible`, which
    /// includes non-fungible and custom assets.
    fn not_fungible_assets(&self) -> impl Iterator<Item = (&AssetVaultKey, &Word)> {
        self.entries.iter().filter(|(key, _value)| !key.composition().is_fungible())
    }
}

impl Serializable for AccountVaultPatch {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.num_not_fungible_assets());
        target.write_many(self.not_fungible_assets());

        target.write_usize(self.num_fungible_assets());
        target.write_many(self.fungible_assets());
    }

    fn get_size_hint(&self) -> usize {
        2 * 0usize.get_size_hint()
            + (AssetVaultKey::SERIALIZED_SIZE + Word::SERIALIZED_SIZE)
                * self.num_not_fungible_assets()
            + (AccountId::SERIALIZED_SIZE
                + AssetCallbackFlag::SERIALIZED_SIZE
                + AssetAmount::SERIALIZED_SIZE)
                * self.num_fungible_assets()
    }
}

impl Deserializable for AccountVaultPatch {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_not_fungible_assets = source.read_usize()?;
        let mut entries: BTreeMap<AssetVaultKey, Word> =
            source.read_many_iter(num_not_fungible_assets)?.collect::<Result<_, _>>()?;

        let num_fungible_assets = source.read_usize()?;
        for result in source.read_many_iter(num_fungible_assets)? {
            let (faucet_id, callback_flag, amount): (AccountId, AssetCallbackFlag, AssetAmount) =
                result?;
            let asset = FungibleAsset::new(faucet_id, amount.as_u64())
                .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?
                .with_callbacks(callback_flag);
            entries.insert(asset.vault_key(), asset.to_value_word());
        }

        Self::new(entries).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::NonFungibleAsset;
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;

    #[test]
    fn account_vault_patch_serde() -> anyhow::Result<()> {
        let empty_patch = AccountVaultPatch::default();
        let serialized = empty_patch.to_bytes();
        let deserialized = AccountVaultPatch::read_from_bytes(&serialized)?;
        assert_eq!(empty_patch, deserialized);
        assert_eq!(empty_patch.get_size_hint(), serialized.len());

        let asset_0 = FungibleAsset::mock(100);
        let asset_1 = FungibleAsset::new(ACCOUNT_ID_PRIVATE_SENDER.try_into()?, 500_000)?.into();
        let asset_2 = NonFungibleAsset::mock(&[10]);
        let asset_3 = NonFungibleAsset::mock(&[20]);
        let patch = AccountVaultPatch::with_assets([asset_0, asset_1, asset_2, asset_3]);

        let serialized = patch.to_bytes();
        let deserialized = AccountVaultPatch::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, patch);
        assert_eq!(patch.get_size_hint(), serialized.len());

        Ok(())
    }
}
