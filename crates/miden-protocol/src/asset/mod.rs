use super::account::AccountType;
use super::errors::{AssetError, TokenSymbolError};
use super::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use super::{Felt, Word};
use crate::account::AccountId;

mod fungible;

pub use fungible::FungibleAsset;

mod nonfungible;

pub use nonfungible::{NonFungibleAsset, NonFungibleAssetDetails};

use crate::FieldElement;

mod token_symbol;
pub use token_symbol::TokenSymbol;

mod vault;
pub use vault::{AssetId, AssetVault, AssetVaultKey, AssetWitness, PartialVault};

// ASSET
// ================================================================================================

/// A fungible or a non-fungible asset.
///
/// All assets are encoded as the vault key of the asset and its value, each represented as one word
/// (4 elements). This makes it is easy to determine the type of an asset both inside and outside
/// Miden VM. Specifically:
///
/// The vault key of an asset contains the [`AccountId`] of the faucet that issues the asset. It can
/// be used to distinguish assets based on the encoded [`AccountId::account_type`]. In the vault
/// keys of assets, the account type bits at index 4 and 5 determine whether the asset is fungible
/// or non-fungible.
///
/// This property guarantees that there can never be a collision between a fungible and a
/// non-fungible asset.
///
/// The methodology for constructing fungible and non-fungible assets is described below.
///
/// # Fungible assets
///
/// - A fungible asset's value layout is: `[amount, 0, 0, 0]`.
/// - A fungible asset's vault key layout is: `[0, 0, faucet_id_suffix, faucet_id_prefix]`.
///
/// The most significant elements of a fungible asset's key are set to the prefix
/// (`faucet_id_prefix`) and suffix (`faucet_id_suffix`) of the ID of the faucet which issues the
/// asset. The asset ID limbs are set to zero, which means two instances of the same fungible asset
/// have the same asset key and will be merged together when stored in the same account's vault.
///
/// The least significant element of the value is set to the amount of the asset and the remaining
/// felts are zero. This amount cannot be greater than [`FungibleAsset::MAX_AMOUNT`] and thus fits
/// into a felt.
///
/// It is impossible to find a collision between two fungible assets issued by different faucets as
/// the faucet ID is included in the description of the asset and this is guaranteed to be different
/// for each faucet as per the faucet creation logic.
///
/// # Non-fungible assets
///
/// - A non-fungible asset's data layout is:      `[hash0, hash1, hash2, hash3]`.
/// - A non-fungible asset's vault key layout is: `[hash0, hash1, faucet_id_suffix,
///   faucet_id_prefix]`.
///
/// The 4 elements of non-fungible assets are computed by hashing the asset data. This compresses an
/// asset of an arbitrary length to 4 field elements: `[hash0, hash1, hash2, hash3]`.
///
/// It is impossible to find a collision between two non-fungible assets issued by different faucets
/// as the faucet ID is included in the description of the non-fungible asset and this is guaranteed
/// to be different as per the faucet creation logic.
///
/// The most significant elements of a non-fungible asset's key are set to the prefix
/// (`faucet_id_prefix`) and suffix (`faucet_id_suffix`) of the ID of the faucet which issues the
/// asset. The asset ID limbs are set to hashes from the asset's value. This means the collision
/// resistance of non-fungible assets issued by the same faucet is ~2^64, due to the 128-bit asset
/// ID that is unique per non-fungible asset. In other words, two non-fungible assets issued by the
/// same faucet are very unlikely to have the same asset key and thus should not collide when stored
/// in the same account's vault.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Asset {
    Fungible(FungibleAsset),
    NonFungible(NonFungibleAsset),
}

impl Asset {
    /// Creates an asset from the provided key and value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`FungibleAsset::from_key_value`] or [`NonFungibleAsset::from_key_value`] fails.
    pub fn from_key_value(key: AssetVaultKey, value: Word) -> Result<Self, AssetError> {
        if matches!(key.faucet_id().account_type(), AccountType::FungibleFaucet) {
            FungibleAsset::from_key_value(key, value).map(Asset::Fungible)
        } else {
            NonFungibleAsset::from_key_value(key, value).map(Asset::NonFungible)
        }
    }

    /// Creates an asset from the provided key and value.
    ///
    /// Prefer [`Self::from_key_value`] for more type safety.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided key does not contain a valid faucet ID.
    /// - [`Self::from_key_value`] fails.
    pub fn from_key_value_words(key: Word, value: Word) -> Result<Self, AssetError> {
        let vault_key = AssetVaultKey::try_from(key)?;
        Self::from_key_value(vault_key, value)
    }

    /// Returns true if this asset is the same as the specified asset.
    ///
    /// Two assets are defined to be the same if:
    /// - For fungible assets, if they were issued by the same faucet.
    /// - For non-fungible assets, if the assets are identical.
    pub fn is_same(&self, other: &Self) -> bool {
        use Asset::*;
        match (self, other) {
            (Fungible(l), Fungible(r)) => l.is_from_same_faucet(r),
            (NonFungible(l), NonFungible(r)) => l == r,
            _ => false,
        }
    }

    /// Returns true if this asset is a fungible asset.
    pub fn is_fungible(&self) -> bool {
        matches!(self, Self::Fungible(_))
    }

    /// Returns true if this asset is a non fungible asset.
    pub fn is_non_fungible(&self) -> bool {
        matches!(self, Self::NonFungible(_))
    }

    /// Returns the ID of the faucet that issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        match self {
            Self::Fungible(asset) => asset.faucet_id(),
            Self::NonFungible(asset) => asset.faucet_id(),
        }
    }

    /// Returns the key which is used to store this asset in the account vault.
    pub fn vault_key(&self) -> AssetVaultKey {
        match self {
            Self::Fungible(asset) => asset.vault_key(),
            Self::NonFungible(asset) => asset.vault_key(),
        }
    }

    /// Returns the asset's key encoded to a [`Word`].
    pub fn to_key_word(&self) -> Word {
        self.vault_key().to_word()
    }

    /// Returns the asset's value encoded to a [`Word`].
    pub fn to_value_word(&self) -> Word {
        match self {
            Asset::Fungible(fungible_asset) => fungible_asset.to_value_word(),
            Asset::NonFungible(non_fungible_asset) => non_fungible_asset.to_value_word(),
        }
    }

    /// Returns the asset encoded as elements.
    ///
    /// The first four elements contain the asset key and the last four elements contain the asset
    /// value.
    pub fn as_elements(&self) -> [Felt; 8] {
        let mut elements = [Felt::ZERO; 8];
        elements[0..4].copy_from_slice(self.to_key_word().as_elements());
        elements[4..8].copy_from_slice(self.to_value_word().as_elements());
        elements
    }

    /// Returns the inner [`FungibleAsset`].
    ///
    /// # Panics
    ///
    /// Panics if the asset is non-fungible.
    pub fn unwrap_fungible(&self) -> FungibleAsset {
        match self {
            Asset::Fungible(asset) => *asset,
            Asset::NonFungible(_) => panic!("the asset is non-fungible"),
        }
    }

    /// Returns the inner [`NonFungibleAsset`].
    ///
    /// # Panics
    ///
    /// Panics if the asset is fungible.
    pub fn unwrap_non_fungible(&self) -> NonFungibleAsset {
        match self {
            Asset::Fungible(_) => panic!("the asset is fungible"),
            Asset::NonFungible(asset) => *asset,
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Asset {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Asset::Fungible(fungible_asset) => fungible_asset.write_into(target),
            Asset::NonFungible(non_fungible_asset) => non_fungible_asset.write_into(target),
        }
    }

    fn get_size_hint(&self) -> usize {
        match self {
            Asset::Fungible(fungible_asset) => fungible_asset.get_size_hint(),
            Asset::NonFungible(non_fungible_asset) => non_fungible_asset.get_size_hint(),
        }
    }
}

impl Deserializable for Asset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Both asset types have their faucet ID as the first element, so we can use it to inspect
        // what type of asset it is.
        let faucet_id: AccountId = source.read()?;

        match faucet_id.account_type() {
            AccountType::FungibleFaucet => {
                FungibleAsset::deserialize_with_faucet_id(faucet_id, source).map(Asset::from)
            },
            AccountType::NonFungibleFaucet => {
                NonFungibleAsset::deserialize_with_faucet_id(faucet_id, source).map(Asset::from)
            },
            other_type => Err(DeserializationError::InvalidValue(format!(
                "failed to deserialize asset: expected an account ID prefix of type faucet, found {other_type}"
            ))),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use miden_crypto::utils::{Deserializable, Serializable};

    use super::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use crate::account::AccountId;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    };

    /// Tests the serialization roundtrip for assets for assets <-> bytes and assets <-> words.
    #[test]
    fn test_asset_serde() -> anyhow::Result<()> {
        for fungible_account_id in [
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ] {
            let account_id = AccountId::try_from(fungible_account_id).unwrap();
            let fungible_asset: Asset = FungibleAsset::new(account_id, 10).unwrap().into();
            assert_eq!(fungible_asset, Asset::read_from_bytes(&fungible_asset.to_bytes()).unwrap());
            assert_eq!(
                fungible_asset,
                Asset::from_key_value_words(
                    fungible_asset.to_key_word(),
                    fungible_asset.to_value_word()
                )?,
            );
        }

        for non_fungible_account_id in [
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
        ] {
            let account_id = AccountId::try_from(non_fungible_account_id).unwrap();
            let details = NonFungibleAssetDetails::new(account_id, vec![1, 2, 3]).unwrap();
            let non_fungible_asset: Asset = NonFungibleAsset::new(&details).unwrap().into();
            assert_eq!(
                non_fungible_asset,
                Asset::read_from_bytes(&non_fungible_asset.to_bytes()).unwrap()
            );
            assert_eq!(
                non_fungible_asset,
                Asset::from_key_value_words(
                    non_fungible_asset.to_key_word(),
                    non_fungible_asset.to_value_word()
                )?
            );
        }

        Ok(())
    }

    /// This test asserts that account ID's is serialized in the first felt of assets.
    /// Asset deserialization relies on that fact and if this changes the serialization must
    /// be updated.
    #[test]
    fn test_account_id_is_serialized_first() {
        for asset in [FungibleAsset::mock(300), NonFungibleAsset::mock(&[0xaa, 0xbb])] {
            let serialized_asset = asset.to_bytes();
            let prefix = AccountId::read_from_bytes(&serialized_asset).unwrap();
            assert_eq!(prefix, asset.faucet_id());
        }
    }
}
