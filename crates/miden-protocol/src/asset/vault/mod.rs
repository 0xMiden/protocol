use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use miden_crypto::merkle::InnerNodeInfo;

use super::{
    Asset,
    AssetAmount,
    AssetComposition,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    FungibleAsset,
    NonFungibleAsset,
    Serializable,
};
use crate::Word;
use crate::account::{AccountVaultDelta, AccountVaultPatch, NonFungibleDeltaAction};
use crate::crypto::merkle::smt::{SMT_DEPTH, Smt};
use crate::errors::{AssetError, AssetVaultError};

mod partial;
pub use partial::PartialVault;

mod asset_witness;
pub use asset_witness::AssetWitness;

mod vault_key;
pub use vault_key::{AssetVaultKey, AssetVaultKeyHash};

mod asset_id;
pub use asset_id::AssetId;

// ASSET VAULT
// ================================================================================================

/// A container for an unlimited number of assets.
///
/// An asset vault can contain an unlimited number of assets. The assets are stored in a Sparse
/// Merkle Tree, keyed by the hash of the [`AssetVaultKey`] (see [`AssetVaultKey::hash`]).
/// Hashing the raw key gives a uniform leaf distribution: in particular it prevents non-fungible
/// assets issued by the same faucet from sharing a leaf, which would otherwise happen because
/// their raw vault keys share their fourth element (the faucet ID prefix) - the element the SMT
/// uses to determine leaf membership.
///
/// The raw (unhashed) [`AssetVaultKey`]s are retained alongside the SMT to allow iteration and
/// proof reconstruction.
///
/// An asset vault can be reduced to a single hash which is the root of the Sparse Merkle Tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetVault {
    /// SMT keyed by hashed [`AssetVaultKey`]s.
    asset_tree: Smt,
    /// Raw [`AssetVaultKey`]s -> asset value words, kept in sync with `asset_tree`.
    entries: BTreeMap<AssetVaultKey, Word>,
}

impl AssetVault {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The depth of the SMT that represents the asset vault.
    pub const DEPTH: u8 = SMT_DEPTH;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [AssetVault] initialized with the provided assets.
    pub fn new(assets: &[Asset]) -> Result<Self, AssetVaultError> {
        let asset_tree = Smt::with_entries(
            assets
                .iter()
                .map(|asset| (asset.vault_key().hash().as_word(), asset.to_value_word())),
        )
        .map_err(AssetVaultError::DuplicateAsset)?;

        // Filter empty values so the `entries` map stays in sync with the SMT, which treats
        // empty values as no-ops. `Smt::with_entries` above already errored on duplicate keys,
        // so collecting into a `BTreeMap` here cannot silently drop assets.
        let entries = assets
            .iter()
            .filter(|asset| !asset.to_value_word().is_empty())
            .map(|asset| (asset.vault_key(), asset.to_value_word()))
            .collect();

        Ok(Self { asset_tree, entries })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the tree root of this vault.
    pub fn root(&self) -> Word {
        self.asset_tree.root()
    }

    /// Returns the asset corresponding to the provided asset vault key, or `None` if the asset
    /// doesn't exist.
    pub fn get(&self, asset_vault_key: AssetVaultKey) -> Option<Asset> {
        let asset_value = self.entries.get(&asset_vault_key).copied().unwrap_or_default();

        if asset_value.is_empty() {
            None
        } else {
            Some(
                Asset::from_key_value(asset_vault_key, asset_value)
                    .expect("asset vault should only store valid assets"),
            )
        }
    }

    /// Returns true if the specified non-fungible asset is stored in this vault.
    pub fn has_non_fungible_asset(&self, asset: NonFungibleAsset) -> Result<bool, AssetVaultError> {
        Ok(self.entries.contains_key(&asset.vault_key()))
    }

    /// Returns the balance of the fungible asset identified by `vault_key`.
    ///
    /// If the vault does not contain the asset, zero is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if `vault_key`'s composition is not [`AssetComposition::Fungible`].
    pub fn get_balance(&self, vault_key: AssetVaultKey) -> Result<AssetAmount, AssetError> {
        if !vault_key.composition().is_fungible() {
            return Err(AssetError::AssetCompositionMismatch {
                faucet_id: vault_key.faucet_id(),
                expected: AssetComposition::Fungible,
                actual: vault_key.composition(),
            });
        }

        let asset_value = self.entries.get(&vault_key).copied().unwrap_or_default();
        let asset = FungibleAsset::from_key_value(vault_key, asset_value)
            .expect("asset vault should only store valid assets");

        Ok(asset.amount())
    }

    /// Returns an iterator over the assets stored in the vault.
    pub fn assets(&self) -> impl Iterator<Item = Asset> + '_ {
        // SAFETY: The entries map only tracks valid assets.
        self.entries.iter().map(|(key, value)| {
            Asset::from_key_value(*key, *value).expect("asset vault should only store valid assets")
        })
    }

    /// Returns an iterator over the inner nodes of the underlying [`Smt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.asset_tree.inner_nodes()
    }

    /// Returns an opening of the leaf associated with `vault_key`.
    ///
    /// The `vault_key` can be obtained with [`Asset::vault_key`].
    pub fn open(&self, vault_key: AssetVaultKey) -> AssetWitness {
        let smt_proof = self.asset_tree.open(&vault_key.hash().as_word());
        let value = self.entries.get(&vault_key).copied().unwrap_or_default();

        // SAFETY: The key-value pair is guaranteed to be present in the proof since we open its
        // hashed form, and the asset vault only contains valid assets.
        AssetWitness::new_unchecked(smt_proof, [(vault_key, value)])
    }

    /// Returns a bool indicating whether the vault is empty.
    pub fn is_empty(&self) -> bool {
        self.asset_tree.is_empty()
    }

    /// Returns the number of non-empty leaves in the underlying [`Smt`].
    ///
    /// Note that this may return a different value from [Self::num_assets()] as a single leaf may
    /// contain more than one asset.
    pub fn num_leaves(&self) -> usize {
        self.asset_tree.num_leaves()
    }

    /// Returns the number of assets in this vault.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one asset.
    pub fn num_assets(&self) -> usize {
        self.asset_tree.num_entries()
    }

    // PUBLIC MODIFIERS
    // --------------------------------------------------------------------------------------------

    /// Applies the specified delta to the asset vault.
    ///
    /// # Errors
    /// Returns an error:
    /// - If the total value of the added assets is greater than [`FungibleAsset::MAX_AMOUNT`].
    /// - If the delta contains an addition/subtraction for a fungible asset that is not stored in
    ///   the vault.
    /// - If the delta contains a non-fungible asset removal that is not stored in the vault.
    /// - If the delta contains a non-fungible asset addition that is already stored in the vault.
    /// - The maximum number of leaves per asset is exceeded.
    pub fn apply_delta(&mut self, delta: &AccountVaultDelta) -> Result<(), AssetVaultError> {
        for (vault_key, &delta) in delta.fungible().iter() {
            // SAFETY: fungible asset delta should only contain fungible faucet IDs and delta amount
            // should be in bounds
            let asset = FungibleAsset::new(vault_key.faucet_id(), delta.unsigned_abs())
                .expect("fungible asset delta should be valid")
                .with_callbacks(vault_key.callback_flag());
            match delta >= 0 {
                true => self.add_fungible_asset(asset),
                false => self.remove_fungible_asset(asset),
            }?;
        }

        for (&asset, &action) in delta.non_fungible().iter() {
            match action {
                NonFungibleDeltaAction::Add => {
                    self.add_non_fungible_asset(asset)?;
                },
                NonFungibleDeltaAction::Remove => {
                    self.remove_non_fungible_asset(asset)?;
                },
            }
        }

        Ok(())
    }

    /// Applies the specified patch to the asset vault.
    ///
    /// This updates each asset that is contained in the patch to its new value.
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum number of leaves per asset is exceeded.
    pub fn apply_patch(&mut self, patch: &AccountVaultPatch) -> Result<(), AssetVaultError> {
        for (&vault_key, &value) in patch.iter() {
            self.insert_entry(vault_key, value)?;
        }

        Ok(())
    }

    // ADD ASSET
    // --------------------------------------------------------------------------------------------
    /// Add the specified asset to the vault.
    ///
    /// # Errors
    /// - If the total value of the added assets is greater than [`FungibleAsset::MAX_AMOUNT`].
    /// - If the vault already contains the same non-fungible asset.
    /// - The maximum number of leaves per asset is exceeded.
    pub fn add_asset(&mut self, asset: Asset) -> Result<Asset, AssetVaultError> {
        Ok(match asset {
            Asset::Fungible(asset) => Asset::Fungible(self.add_fungible_asset(asset)?),
            Asset::NonFungible(asset) => Asset::NonFungible(self.add_non_fungible_asset(asset)?),
        })
    }

    /// Add the specified fungible asset to the vault. If the vault already contains an asset
    /// issued by the same faucet, the amounts are added together.
    ///
    /// # Errors
    /// - If the total value of the added assets is greater than [`FungibleAsset::MAX_AMOUNT`].
    /// - The maximum number of leaves per asset is exceeded.
    fn add_fungible_asset(
        &mut self,
        other_asset: FungibleAsset,
    ) -> Result<FungibleAsset, AssetVaultError> {
        let vault_key = other_asset.vault_key();
        let current_asset_value = self.entries.get(&vault_key).copied().unwrap_or_default();
        let current_asset = FungibleAsset::from_key_value(vault_key, current_asset_value)
            .expect("asset vault should store valid assets");

        let new_asset = current_asset
            .add(other_asset)
            .map_err(AssetVaultError::AddFungibleAssetBalanceError)?;

        self.insert_entry(new_asset.vault_key(), new_asset.to_value_word())?;

        Ok(new_asset)
    }

    /// Add the specified non-fungible asset to the vault.
    ///
    /// # Errors
    /// - If the vault already contains the same non-fungible asset.
    /// - The maximum number of leaves per asset is exceeded.
    fn add_non_fungible_asset(
        &mut self,
        asset: NonFungibleAsset,
    ) -> Result<NonFungibleAsset, AssetVaultError> {
        let old = self.insert_entry(asset.vault_key(), asset.to_value_word())?;

        // if the asset already exists, return an error
        if old != Smt::EMPTY_VALUE {
            return Err(AssetVaultError::DuplicateNonFungibleAsset(asset));
        }

        Ok(asset)
    }

    // REMOVE ASSET
    // --------------------------------------------------------------------------------------------
    /// Remove the specified asset from the vault and returns the remaining asset, if any.
    ///
    /// - For fungible assets, returns `Some(Asset::Fungible(remaining))` with the remaining balance
    ///   (which may have amount 0).
    /// - For non-fungible assets, returns `None` since non-fungible assets are either fully present
    ///   or absent.
    ///
    /// # Errors
    /// - The fungible asset is not found in the vault.
    /// - The amount of the fungible asset in the vault is less than the amount to be removed.
    /// - The non-fungible asset is not found in the vault.
    pub fn remove_asset(&mut self, asset: Asset) -> Result<Option<Asset>, AssetVaultError> {
        match asset {
            Asset::Fungible(asset) => {
                let remaining = self.remove_fungible_asset(asset)?;
                Ok(Some(Asset::Fungible(remaining)))
            },
            Asset::NonFungible(asset) => {
                self.remove_non_fungible_asset(asset)?;
                Ok(None)
            },
        }
    }

    /// Remove the specified fungible asset from the vault and returns the remaining fungible
    /// asset. If the final amount of the asset is zero, the asset is removed from the vault.
    ///
    /// # Errors
    /// - The asset is not found in the vault.
    /// - The amount of the asset in the vault is less than the amount to be removed.
    /// - The maximum number of leaves per asset is exceeded.
    fn remove_fungible_asset(
        &mut self,
        other_asset: FungibleAsset,
    ) -> Result<FungibleAsset, AssetVaultError> {
        let vault_key = other_asset.vault_key();
        let current_asset_value = self.entries.get(&vault_key).copied().unwrap_or_default();
        let current_asset = FungibleAsset::from_key_value(vault_key, current_asset_value)
            .expect("asset vault should store valid assets");

        // If the asset's amount is 0, we consider it absent from the vault.
        if current_asset.amount() == AssetAmount::ZERO {
            return Err(AssetVaultError::FungibleAssetNotFound(other_asset));
        }

        let new_asset = current_asset
            .sub(other_asset)
            .map_err(AssetVaultError::SubtractFungibleAssetBalanceError)?;

        // Note that if new_asset's amount is 0, its value's word representation is equal to
        // the empty word, which results in the removal of the entire entry from the corresponding
        // leaf.
        #[cfg(debug_assertions)]
        {
            if new_asset.amount() == AssetAmount::ZERO {
                assert!(new_asset.to_value_word().is_empty())
            }
        }

        self.insert_entry(new_asset.vault_key(), new_asset.to_value_word())?;

        Ok(new_asset)
    }

    /// Remove the specified non-fungible asset from the vault.
    ///
    /// # Errors
    /// - The non-fungible asset is not found in the vault.
    /// - The maximum number of leaves per asset is exceeded.
    fn remove_non_fungible_asset(
        &mut self,
        asset: NonFungibleAsset,
    ) -> Result<(), AssetVaultError> {
        let old = self.insert_entry(asset.vault_key(), Smt::EMPTY_VALUE)?;

        // return an error if the asset did not exist in the vault.
        if old == Smt::EMPTY_VALUE {
            return Err(AssetVaultError::NonFungibleAssetNotFound(asset));
        }

        Ok(())
    }

    /// Inserts the given `(vault_key, value)` pair into both the SMT and the raw-entry map.
    ///
    /// Returns the previous SMT value at the hashed key (the empty word if no entry existed).
    fn insert_entry(
        &mut self,
        vault_key: AssetVaultKey,
        value: Word,
    ) -> Result<Word, AssetVaultError> {
        // Insert into the SMT first so that `entries` is only mutated once the fallible insert
        // succeeds; this keeps the two structures in sync even if the insert errors.
        let old_value = self
            .asset_tree
            .insert(vault_key.hash().into(), value)
            .map_err(AssetVaultError::MaxLeafEntriesExceeded)?;

        if value == Smt::EMPTY_VALUE {
            self.entries.remove(&vault_key);
        } else {
            self.entries.insert(vault_key, value);
        }

        Ok(old_value)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AssetVault {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let num_assets = self.asset_tree.num_entries();
        target.write_usize(num_assets);
        target.write_many(self.assets());
    }

    fn get_size_hint(&self) -> usize {
        let mut size = 0;
        let mut count: usize = 0;

        for asset in self.assets() {
            size += asset.get_size_hint();
            count += 1;
        }

        size += count.get_size_hint();

        size
    }
}

impl Deserializable for AssetVault {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_assets = source.read_usize()?;
        let assets = source.read_many_iter::<Asset>(num_assets)?.collect::<Result<Vec<_>, _>>()?;
        Self::new(&assets).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn vault_fails_on_absent_fungible_asset() {
        let mut vault = AssetVault::default();
        let err = vault.remove_asset(FungibleAsset::mock(50)).unwrap_err();
        assert_matches!(err, AssetVaultError::FungibleAssetNotFound(_));
    }

    /// Two non-fungible assets issued by the same faucet share their fourth raw-key element (the
    /// faucet ID prefix), which historically caused them to land in the same SMT leaf because the
    /// SMT uses element 3 for leaf membership. Hashing the vault key before insertion fixes that:
    /// the assets must end up in different leaves.
    ///
    /// Regression test for <https://github.com/0xMiden/protocol/issues/2518>.
    #[test]
    fn two_non_fungible_assets_from_same_faucet_use_different_leaves() -> anyhow::Result<()> {
        let asset0 = NonFungibleAsset::mock(&[1, 2, 3]);
        let asset1 = NonFungibleAsset::mock(&[4, 5, 6]);

        // Sanity check: the assets share their faucet but have distinct raw vault keys (different
        // asset IDs).
        assert_eq!(asset0.vault_key().faucet_id(), asset1.vault_key().faucet_id());
        assert_ne!(asset0.vault_key(), asset1.vault_key());

        // Without hashing, both raw vault keys share their two most significant elements (the
        // faucet ID suffix/metadata in element 2 and the faucet ID prefix in element 3). Element 3
        // is what the SMT uses for leaf membership, so the two would collide into a single leaf.
        // Sanity-check that pre-condition.
        assert_eq!(asset0.vault_key().to_word()[2], asset1.vault_key().to_word()[2]);
        assert_eq!(asset0.vault_key().to_word()[3], asset1.vault_key().to_word()[3]);

        // With hashing, the hashed leaf indices differ, so they live in different SMT leaves.
        assert_ne!(
            asset0.vault_key().hash().to_leaf_index(),
            asset1.vault_key().hash().to_leaf_index()
        );

        let vault = AssetVault::new(&[asset0, asset1])?;
        assert_eq!(vault.num_leaves(), 2);
        assert_eq!(vault.num_assets(), 2);

        Ok(())
    }
}
