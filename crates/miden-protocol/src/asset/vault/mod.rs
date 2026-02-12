use alloc::string::ToString;

use miden_crypto::merkle::InnerNodeInfo;
use miden_processor::SMT_DEPTH;

use super::{
    AccountType,
    Asset,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    FungibleAsset,
    NonFungibleAsset,
    Serializable,
};
use crate::Word;
use crate::account::{AccountId, AccountVaultDelta, NonFungibleDeltaAction};
use crate::crypto::merkle::smt::Smt;
use crate::errors::AssetVaultError;

mod partial;
pub use partial::PartialVault;

mod asset_witness;
pub use asset_witness::AssetWitness;

mod vault_key;
pub use vault_key::AssetVaultKey;

// ASSET VAULT
// ================================================================================================

/// A container for an unlimited number of assets.
///
/// An asset vault can contain an unlimited number of assets. The assets are stored in a Sparse
/// Merkle tree as follows:
/// - For fungible assets, the index of a node is defined by the issuing faucet ID, and the value of
///   the node is the asset itself. Thus, for any fungible asset there will be only one node in the
///   tree.
/// - For non-fungible assets, the index is defined by the asset itself, and the asset is also the
///   value of the node.
///
/// An asset vault can be reduced to a single hash which is the root of the Sparse Merkle Tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetVault {
    asset_tree: Smt,
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
        Ok(Self {
            asset_tree: Smt::with_entries(
                assets.iter().map(|asset| (asset.vault_key().into(), (*asset).into())),
            )
            .map_err(AssetVaultError::DuplicateAsset)?,
        })
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
        let word = self.asset_tree.get_value(asset_vault_key.as_word());

        if word.is_empty() {
            None
        } else {
            Some(Asset::try_from(word).expect("asset vault should only store valid assets"))
        }
    }

    /// Returns true if the specified non-fungible asset is stored in this vault.
    pub fn has_non_fungible_asset(&self, asset: NonFungibleAsset) -> Result<bool, AssetVaultError> {
        // check if the asset is stored in the vault
        match self.asset_tree.get_value(&asset.vault_key().into()) {
            asset if asset == Smt::EMPTY_VALUE => Ok(false),
            _ => Ok(true),
        }
    }

    /// Returns the balance of the asset issued by the specified faucet. If the vault does not
    /// contain such an asset, 0 is returned.
    ///
    /// # Errors
    /// Returns an error if the specified ID is not an ID of a fungible asset faucet.
    pub fn get_balance(&self, faucet_id: AccountId) -> Result<u64, AssetVaultError> {
        if !matches!(faucet_id.account_type(), AccountType::FungibleFaucet) {
            return Err(AssetVaultError::NotAFungibleFaucetId(faucet_id));
        }

        // if the tree value is [0, 0, 0, 0], the asset is not stored in the vault
        match self.asset_tree.get_value(
            &AssetVaultKey::from_account_id(faucet_id)
                .expect("faucet ID should be of type fungible")
                .into(),
        ) {
            asset if asset == Smt::EMPTY_VALUE => Ok(0),
            asset => Ok(FungibleAsset::new_unchecked(asset).amount()),
        }
    }

    /// Returns an iterator over the assets stored in the vault.
    pub fn assets(&self) -> impl Iterator<Item = Asset> + '_ {
        // SAFETY: The asset tree tracks only valid assets.
        self.asset_tree.entries().map(|(_key, value)| Asset::new_unchecked(*value))
    }

    /// Returns an iterator over the inner nodes of the underlying [`Smt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.asset_tree.inner_nodes()
    }

    /// Returns an opening of the leaf associated with `vault_key`.
    ///
    /// The `vault_key` can be obtained with [`Asset::vault_key`].
    pub fn open(&self, vault_key: AssetVaultKey) -> AssetWitness {
        let smt_proof = self.asset_tree.open(&vault_key.into());
        // SAFETY: The asset vault should only contain valid assets.
        AssetWitness::new_unchecked(smt_proof)
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
    /// - If the total value of assets is greater than or equal to 2^63.
    /// - If the delta contains an addition/subtraction for a fungible asset that is not stored in
    ///   the vault.
    /// - If the delta contains a non-fungible asset removal that is not stored in the vault.
    /// - If the delta contains a non-fungible asset addition that is already stored in the vault.
    /// - The maximum number of leaves per asset is exceeded.
    pub fn apply_delta(&mut self, delta: &AccountVaultDelta) -> Result<(), AssetVaultError> {
        for (&faucet_id, &delta) in delta.fungible().iter() {
            let asset = FungibleAsset::new(faucet_id, delta.unsigned_abs())
                .expect("Not a fungible faucet ID or delta is too large");
            match delta >= 0 {
                true => self.add_fungible_asset(asset),
                false => self.remove_fungible_asset(asset),
            }?;
        }

        for (&asset, &action) in delta.non_fungible().iter() {
            match action {
                NonFungibleDeltaAction::Add => self.add_non_fungible_asset(asset),
                NonFungibleDeltaAction::Remove => self.remove_non_fungible_asset(asset),
            }?;
        }

        Ok(())
    }

    // ADD ASSET
    // --------------------------------------------------------------------------------------------
    /// Add the specified asset to the vault.
    ///
    /// # Errors
    /// - If the total value of two fungible assets is greater than or equal to 2^63.
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
    /// - If the total value of assets is greater than or equal to 2^63.
    /// - The maximum number of leaves per asset is exceeded.
    fn add_fungible_asset(
        &mut self,
        asset: FungibleAsset,
    ) -> Result<FungibleAsset, AssetVaultError> {
        // fetch current asset value from the tree and add the new asset to it.
        let new: FungibleAsset = match self.asset_tree.get_value(&asset.vault_key().into()) {
            current if current == Smt::EMPTY_VALUE => asset,
            current => {
                let current = FungibleAsset::new_unchecked(current);
                current.add(asset).map_err(AssetVaultError::AddFungibleAssetBalanceError)?
            },
        };
        self.asset_tree
            .insert(new.vault_key().into(), new.into())
            .map_err(AssetVaultError::MaxLeafEntriesExceeded)?;

        // return the new asset
        Ok(new)
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
        // add non-fungible asset to the vault
        let old = self
            .asset_tree
            .insert(asset.vault_key().into(), asset.into())
            .map_err(AssetVaultError::MaxLeafEntriesExceeded)?;

        // if the asset already exists, return an error
        if old != Smt::EMPTY_VALUE {
            return Err(AssetVaultError::DuplicateNonFungibleAsset(asset));
        }

        Ok(asset)
    }

    // REMOVE ASSET
    // --------------------------------------------------------------------------------------------
    /// Remove the specified asset from the vault and returns the asset that was just removed.
    ///
    /// # Errors
    /// - The fungible asset is not found in the vault.
    /// - The amount of the fungible asset in the vault is less than the amount to be removed.
    /// - The non-fungible asset is not found in the vault.
    pub fn remove_asset(&mut self, asset: Asset) -> Result<Asset, AssetVaultError> {
        match asset {
            Asset::Fungible(asset) => {
                let asset = self.remove_fungible_asset(asset)?;
                Ok(Asset::Fungible(asset))
            },
            Asset::NonFungible(asset) => {
                let asset = self.remove_non_fungible_asset(asset)?;
                Ok(Asset::NonFungible(asset))
            },
        }
    }

    /// Remove the specified fungible asset from the vault and returns the asset that was just
    /// removed. If the final amount of the asset is zero, the asset is removed from the vault.
    ///
    /// # Errors
    /// - The asset is not found in the vault.
    /// - The amount of the asset in the vault is less than the amount to be removed.
    /// - The maximum number of leaves per asset is exceeded.
    fn remove_fungible_asset(
        &mut self,
        asset: FungibleAsset,
    ) -> Result<FungibleAsset, AssetVaultError> {
        // fetch the asset from the vault.
        let new: FungibleAsset = match self.asset_tree.get_value(&asset.vault_key().into()) {
            current if current == Smt::EMPTY_VALUE => {
                return Err(AssetVaultError::FungibleAssetNotFound(asset));
            },
            current => {
                let current = FungibleAsset::new_unchecked(current);
                current.sub(asset).map_err(AssetVaultError::SubtractFungibleAssetBalanceError)?
            },
        };

        // if the amount of the asset is zero, remove the asset from the vault.
        let value = match new.amount() {
            0 => Smt::EMPTY_VALUE,
            _ => new.into(),
        };
        self.asset_tree
            .insert(new.vault_key().into(), value)
            .map_err(AssetVaultError::MaxLeafEntriesExceeded)?;

        // return the asset that was removed.
        Ok(asset)
    }

    /// Remove the specified non-fungible asset from the vault and returns the asset that was just
    /// removed.
    ///
    /// # Errors
    /// - The non-fungible asset is not found in the vault.
    /// - The maximum number of leaves per asset is exceeded.
    fn remove_non_fungible_asset(
        &mut self,
        asset: NonFungibleAsset,
    ) -> Result<NonFungibleAsset, AssetVaultError> {
        // remove the asset from the vault.
        let old = self
            .asset_tree
            .insert(asset.vault_key().into(), Smt::EMPTY_VALUE)
            .map_err(AssetVaultError::MaxLeafEntriesExceeded)?;

        // return an error if the asset did not exist in the vault.
        if old == Smt::EMPTY_VALUE {
            return Err(AssetVaultError::NonFungibleAssetNotFound(asset));
        }

        // return the asset that was removed.
        Ok(asset)
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
        let assets = source.read_many::<Asset>(num_assets)?;
        Self::new(&assets).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
