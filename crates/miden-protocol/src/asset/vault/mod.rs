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
    Serializable,
};
use crate::Word;
use crate::account::AccountVaultPatch;
use crate::crypto::merkle::smt::{SMT_DEPTH, Smt};
use crate::errors::{AssetError, AssetVaultError};

mod partial;
pub use partial::PartialVault;

mod asset_witness;
pub use asset_witness::AssetWitness;

mod asset_id;
pub use asset_id::{AssetId, AssetIdHash};

mod asset_class;
pub use asset_class::AssetClass;

// ASSET VAULT
// ================================================================================================

/// A container for an unlimited number of assets.
///
/// An asset vault can contain an unlimited number of assets. The assets are stored in a Sparse
/// Merkle Tree, keyed by the hash of the [`AssetId`] (see [`AssetId::hash`]).
/// Hashing the raw asset ID gives a uniform leaf distribution: in particular it prevents
/// non-fungible assets issued by the same faucet from sharing a leaf, which would otherwise happen
/// because their raw asset IDs share their fourth element (the faucet ID prefix) - the element the
/// SMT uses to determine leaf membership.
///
/// The raw (unhashed) [`AssetId`]s are retained alongside the SMT to allow iteration and
/// proof reconstruction.
///
/// An asset vault can be reduced to a single hash which is the root of the Sparse Merkle Tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetVault {
    /// SMT keyed by hashed [`AssetId`]s.
    asset_tree: Smt,
    /// Raw [`AssetId`]s -> asset value words, kept in sync with `asset_tree`.
    entries: BTreeMap<AssetId, Word>,
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
            assets.iter().map(|asset| (asset.id().hash().as_word(), asset.to_value_word())),
        )
        .map_err(AssetVaultError::DuplicateAsset)?;

        // Filter empty values so the `entries` map stays in sync with the SMT, which treats
        // empty values as no-ops. `Smt::with_entries` above already errored on duplicate keys,
        // so collecting into a `BTreeMap` here cannot silently drop assets.
        let entries = assets
            .iter()
            .filter(|asset| !asset.to_value_word().is_empty())
            .map(|asset| (asset.id(), asset.to_value_word()))
            .collect();

        Ok(Self { asset_tree, entries })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the tree root of this vault.
    pub fn root(&self) -> Word {
        self.asset_tree.root()
    }

    /// Returns the asset corresponding to the provided asset ID, or `None` if the asset
    /// doesn't exist.
    pub fn get(&self, asset_id: AssetId) -> Option<Asset> {
        let asset_value = self.entries.get(&asset_id).copied().unwrap_or_default();

        if asset_value.is_empty() {
            None
        } else {
            Some(
                Asset::new(asset_id, asset_value)
                    .expect("asset vault should only store valid assets"),
            )
        }
    }

    /// Returns the balance of the fungible asset identified by `asset_id`.
    ///
    /// If the vault does not contain the asset, zero is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if `asset_id`'s composition is not [`AssetComposition::Fungible`].
    pub fn get_balance(&self, asset_id: AssetId) -> Result<AssetAmount, AssetError> {
        if !asset_id.composition().is_fungible() {
            return Err(AssetError::AssetCompositionMismatch {
                faucet_id: asset_id.faucet_id(),
                expected: AssetComposition::Fungible,
                actual: asset_id.composition(),
            });
        }

        let asset_value = self.entries.get(&asset_id).copied().unwrap_or_default();
        let asset = FungibleAsset::from_id_and_value(asset_id, asset_value)
            .expect("asset vault should only store valid assets");

        Ok(asset.amount())
    }

    /// Returns an iterator over the assets stored in the vault.
    pub fn assets(&self) -> impl Iterator<Item = Asset> + '_ {
        // SAFETY: The entries map only tracks valid assets.
        self.entries.iter().map(|(id, value)| {
            Asset::new(*id, *value).expect("asset vault should only store valid assets")
        })
    }

    /// Returns an iterator over the inner nodes of the underlying [`Smt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.asset_tree.inner_nodes()
    }

    /// Returns an opening of the leaf associated with `asset_id`.
    ///
    /// The `asset_id` can be obtained with [`Asset::id`].
    pub fn open(&self, asset_id: AssetId) -> AssetWitness {
        let smt_proof = self.asset_tree.open(&asset_id.hash().as_word());
        let value = self.entries.get(&asset_id).copied().unwrap_or_default();

        // SAFETY: The ID-value pair is guaranteed to be present in the proof since we open its
        // hashed form, and the asset vault only contains valid assets.
        AssetWitness::new_unchecked(smt_proof, [(asset_id, value)])
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

    /// Applies the specified patch to the asset vault.
    ///
    /// This updates each asset that is contained in the patch to its new value.
    ///
    /// # Errors
    ///
    /// Returns an error if the maximum number of leaves per asset is exceeded.
    pub fn apply_patch(&mut self, patch: &AccountVaultPatch) -> Result<(), AssetVaultError> {
        for (&asset_id, &value) in patch.iter() {
            self.insert_entry(asset_id, value)?;
        }

        Ok(())
    }

    // ADD ASSET
    // --------------------------------------------------------------------------------------------

    /// Inserts the specified asset into the vault, overwriting the asset value at the same asset
    /// ID. Returns the value of the asset previously.
    ///
    /// # Errors
    /// - The maximum number of leaves per asset is exceeded.
    pub fn insert_asset(&mut self, asset: Asset) -> Result<Word, AssetVaultError> {
        self.insert_entry(asset.id(), asset.to_value_word())
    }

    /// Add the specified asset to the vault.
    ///
    /// # Errors
    /// - If the total value of the added assets is greater than [`FungibleAsset::MAX_AMOUNT`].
    /// - If the vault already contains the same non-fungible asset.
    /// - The maximum number of leaves per asset is exceeded.
    pub fn add_asset(&mut self, asset: Asset) -> Result<Asset, AssetVaultError> {
        match asset.as_fungible() {
            Some(fungible_asset) => Ok(self.add_fungible_asset(fungible_asset)?.into()),
            None => self.add_non_fungible_asset(asset),
        }
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
        let asset_id = other_asset.id();
        let current_asset_value = self.entries.get(&asset_id).copied().unwrap_or_default();
        let current_asset = FungibleAsset::from_id_and_value(asset_id, current_asset_value)
            .expect("asset vault should store valid assets");

        let new_asset = current_asset
            .add(other_asset)
            .map_err(AssetVaultError::AddFungibleAssetBalanceError)?;

        self.insert_entry(new_asset.id(), new_asset.to_value_word())?;

        Ok(new_asset)
    }

    /// Add the specified non-fungible asset to the vault.
    ///
    /// # Errors
    /// - If the vault already contains the same non-fungible asset.
    /// - The maximum number of leaves per asset is exceeded.
    fn add_non_fungible_asset(&mut self, asset: Asset) -> Result<Asset, AssetVaultError> {
        let old = self.insert_entry(asset.id(), asset.to_value_word())?;

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
    /// - For fungible assets, returns `Some` with the remaining balance (which may have amount 0).
    /// - For non-fungible assets, returns `None` since non-fungible assets are either fully present
    ///   or absent.
    ///
    /// # Errors
    /// - The fungible asset is not found in the vault.
    /// - The amount of the fungible asset in the vault is less than the amount to be removed.
    /// - The non-fungible asset is not found in the vault.
    pub fn remove_asset(&mut self, asset: Asset) -> Result<Option<Asset>, AssetVaultError> {
        match asset.as_fungible() {
            Some(fungible_asset) => {
                let remaining = self.remove_fungible_asset(fungible_asset)?;
                Ok(Some(remaining.into()))
            },
            None => {
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
        let asset_id = other_asset.id();
        let current_asset_value = self.entries.get(&asset_id).copied().unwrap_or_default();
        let current_asset = FungibleAsset::from_id_and_value(asset_id, current_asset_value)
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

        self.insert_entry(new_asset.id(), new_asset.to_value_word())?;

        Ok(new_asset)
    }

    /// Remove the specified non-fungible asset from the vault.
    ///
    /// # Errors
    /// - The non-fungible asset is not found in the vault.
    /// - The maximum number of leaves per asset is exceeded.
    fn remove_non_fungible_asset(&mut self, asset: Asset) -> Result<(), AssetVaultError> {
        let old = self.insert_entry(asset.id(), Smt::EMPTY_VALUE)?;

        // return an error if the asset did not exist in the vault.
        if old == Smt::EMPTY_VALUE {
            return Err(AssetVaultError::NonFungibleAssetNotFound(asset));
        }

        Ok(())
    }

    /// Inserts the given `(asset_id, value)` pair into both the SMT and the raw-entry map.
    ///
    /// Returns the previous SMT value at the hashed key (the empty word if no entry existed).
    fn insert_entry(&mut self, asset_id: AssetId, value: Word) -> Result<Word, AssetVaultError> {
        // Insert into the SMT first so that `entries` is only mutated once the fallible insert
        // succeeds; this keeps the two structures in sync even if the insert errors.
        let old_value = self
            .asset_tree
            .insert(asset_id.hash().into(), value)
            .map_err(AssetVaultError::MaxLeafEntriesExceeded)?;

        if value == Smt::EMPTY_VALUE {
            self.entries.remove(&asset_id);
        } else {
            self.entries.insert(asset_id, value);
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
    use crate::asset::NonFungibleAsset;

    #[test]
    fn vault_fails_on_absent_fungible_asset() {
        let mut vault = AssetVault::default();
        let err = vault.remove_asset(FungibleAsset::mock(50)).unwrap_err();
        assert_matches!(err, AssetVaultError::FungibleAssetNotFound(_));
    }

    /// Two non-fungible assets issued by the same faucet share their fourth raw-ID element (the
    /// faucet ID prefix), which historically caused them to land in the same SMT leaf because the
    /// SMT uses element 3 for leaf membership. Hashing the asset ID before insertion fixes that:
    /// the assets must end up in different leaves.
    ///
    /// Regression test for <https://github.com/0xMiden/protocol/issues/2518>.
    #[test]
    fn two_non_fungible_assets_from_same_faucet_use_different_leaves() -> anyhow::Result<()> {
        let asset0 = NonFungibleAsset::mock(&[1, 2, 3]);
        let asset1 = NonFungibleAsset::mock(&[4, 5, 6]);

        // Sanity check: the assets share their faucet but have distinct raw asset IDs (different
        // asset class).
        assert_eq!(asset0.id().faucet_id(), asset1.id().faucet_id());
        assert_ne!(asset0.id(), asset1.id());

        // Without hashing, both raw asset IDs share their two most significant elements (the
        // faucet ID suffix/metadata in element 2 and the faucet ID prefix in element 3). Element 3
        // is what the SMT uses for leaf membership, so the two would collide into a single leaf.
        // Sanity-check that pre-condition.
        assert_eq!(asset0.id().to_word()[2], asset1.id().to_word()[2]);
        assert_eq!(asset0.id().to_word()[3], asset1.id().to_word()[3]);

        // With hashing, the hashed leaf indices differ, so they live in different SMT leaves.
        assert_ne!(asset0.id().hash().to_leaf_index(), asset1.id().hash().to_leaf_index());

        let vault = AssetVault::new(&[asset0, asset1])?;
        assert_eq!(vault.num_leaves(), 2);
        assert_eq!(vault.num_assets(), 2);

        Ok(())
    }
}
