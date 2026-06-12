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

mod asset_amount;
pub use asset_amount::AssetAmount;

mod fungible;

pub use fungible::FungibleAsset;

mod nonfungible;

pub use nonfungible::{NonFungibleAsset, NonFungibleAssetDetails};

mod token_symbol;
pub use token_symbol::TokenSymbol;

mod asset_callbacks;
pub use asset_callbacks::AssetCallbacks;

mod asset_callbacks_flag;
pub use asset_callbacks_flag::AssetCallbackFlag;

mod asset_composition;
pub use asset_composition::AssetComposition;

mod vault;
pub use vault::{
    AssetId,
    AssetVault,
    AssetVaultKey,
    AssetVaultKeyHash,
    AssetWitness,
    PartialVault,
};

// ASSET
// ================================================================================================

/// A fungible or a non-fungible asset.
///
/// All assets are encoded as the vault key of the asset and its value, each represented as one word
/// (4 elements). This makes it is easy to determine the type of an asset both inside and outside
/// Miden VM. Specifically:
///
/// The vault key of an asset contains the [`AssetComposition`] which describes how assets compose,
/// meaning whether they can be merged or split.
///
/// This property guarantees that there can never be a collision between a fungible and a
/// non-fungible asset.
///
/// The methodology for constructing fungible and non-fungible assets is described below.
///
/// # Fungible assets
///
/// - A fungible asset's value layout is: `[amount, 0, 0, 0]`.
/// - A fungible asset's vault key layout is: `[0, 0, faucet_id_suffix_and_metadata,
///   faucet_id_prefix]`.
///
/// Where:
/// - `amount` is the [`AssetAmount`] that the asset holds and cannot be greater than
///   [`AssetAmount::MAX`] and thus fits into a felt.
/// - the remaining elements in the value word must be zero.
/// - `faucet_id_prefix` is the prefix of the faucet ID which issues the asset.
/// - `faucet_id_suffix_and_metadata` is the suffix of the faucet ID which issues the asset and the
///   asset metadata ([`AssetCallbackFlag`] and [`AssetComposition`]). See [`AssetVaultKey`] for
///   more details on the key's layout.
/// - the asset ID limbs must be zero, which means two instances of the same fungible asset have the
///   same asset key and will be merged together when stored in the same account's vault.
///
/// It is impossible to find a collision between two fungible assets issued by different faucets as
/// the faucet ID is part of the asset's vault key and this is guaranteed to be different for each
/// faucet as per the faucet creation logic.
///
/// # Non-fungible assets
///
/// - A non-fungible asset's data layout is:      `[hash0, hash1, hash2, hash3]`.
/// - A non-fungible asset's vault key layout is: `[hash0, hash1, faucet_id_suffix_and_metadata,
///   faucet_id_prefix]`.
///
/// Where:
/// - the 4 elements of non-fungible asset values are computed by hashing the asset data. This
///   compresses an asset of an arbitrary length to 4 field elements.
/// - `faucet_id_prefix` is the prefix of the faucet ID which issues the asset.
/// - `faucet_id_suffix_and_metadata` is the suffix of the faucet ID which issues the asset and the
///   asset metadata ([`AssetCallbackFlag`] and [`AssetComposition`]). See [`AssetVaultKey`] for
///   more details on the key's layout.
/// - The asset ID limbs are set to hashes from the asset's value (`hash0` and `hash1`).
///
/// It is impossible to find a collision between two non-fungible assets issued by different faucets
/// as the faucet ID is part of the asset's vault key and this is guaranteed to be different as per
/// the faucet creation logic.
///
/// The collision resistance of non-fungible assets issued by the same faucet is ~2^64, due to the
/// 128-bit asset ID that is unique per non-fungible asset. In other words, two non-fungible assets
/// issued by the same faucet are very unlikely to have the same asset key and thus should not
/// collide when stored in the same account's vault.
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
        match key.composition() {
            AssetComposition::Fungible => {
                FungibleAsset::from_key_value(key, value).map(Asset::Fungible)
            },
            AssetComposition::None => {
                NonFungibleAsset::from_key_value(key, value).map(Asset::NonFungible)
            },
            AssetComposition::Custom => {
                Err(AssetError::UnsupportedAssetComposition(AssetComposition::Custom))
            },
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

    /// Returns a copy of this asset with the given [`AssetCallbackFlag`].
    pub fn with_callbacks(self, callbacks: AssetCallbackFlag) -> Self {
        match self {
            Asset::Fungible(fungible_asset) => fungible_asset.with_callbacks(callbacks).into(),
            Asset::NonFungible(non_fungible_asset) => {
                non_fungible_asset.with_callbacks(callbacks).into()
            },
        }
    }

    /// Returns true if this asset is the same as the specified asset.
    ///
    /// Two assets are defined to be the same if their vault keys match.
    pub fn is_same(&self, other: &Self) -> bool {
        self.vault_key() == other.vault_key()
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
        // All assets have their composition serialized as the first byte, so we can use it to
        // inspect what type of asset it is.
        let composition: AssetComposition = source.read()?;
        match composition {
            AssetComposition::Fungible => FungibleAsset::deserialize_body(source).map(Asset::from),
            AssetComposition::None => NonFungibleAsset::deserialize_body(source).map(Asset::from),
            AssetComposition::Custom => Err(DeserializationError::InvalidValue(
                "Custom asset composition is not supported".into(),
            )),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use miden_core::Word;
    use miden_crypto::utils::{Deserializable, Serializable};

    use super::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
    use crate::Felt;
    use crate::account::AccountId;
    use crate::asset::{AssetCallbackFlag, AssetComposition, AssetId, AssetVaultKey};
    use crate::errors::AssetError;
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

    /// Returns the metadata byte encoded in a vault-key word.
    pub(super) fn asset_metadata(key: AssetVaultKey) -> u8 {
        (key.to_word()[2].as_canonical_u64() & AssetVaultKey::METADATA_BYTE_MASK as u64) as u8
    }

    /// Overwrites the metadata byte of the third element of a key word.
    pub(super) fn set_asset_metadata(key: AssetVaultKey, byte: u8) -> Word {
        let mut key = key.to_word();
        let raw = key[2].as_canonical_u64();
        let new_raw = (raw & !(AssetVaultKey::METADATA_BYTE_MASK as u64)) | byte as u64;
        key[2] = Felt::try_from(new_raw).expect("clearing lower bits should produce a valid felt");
        key
    }

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
            let details = NonFungibleAssetDetails::new(account_id, vec![1, 2, 3]);
            let non_fungible_asset: Asset = NonFungibleAsset::new(&details).into();
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

    /// Asserts that every fully-serialized asset leads with an [`AssetComposition`] byte that
    /// reflects the asset variant. Asset deserialization relies on this discriminator.
    #[test]
    fn test_composition_byte_is_serialized_first() {
        let fungible_bytes = FungibleAsset::mock(300).to_bytes();
        assert_eq!(fungible_bytes[0], AssetComposition::Fungible.as_u8());

        let non_fungible_bytes = NonFungibleAsset::mock(&[0xaa, 0xbb]).to_bytes();
        assert_eq!(non_fungible_bytes[0], AssetComposition::None.as_u8());
    }

    /// `Asset::from_key_value` must reject a [`AssetComposition::Custom`] key with
    /// `UnsupportedAssetComposition`.
    #[test]
    fn test_from_key_value_rejects_custom_composition() -> anyhow::Result<()> {
        let err = AssetVaultKey::new(
            AssetId::default(),
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?,
            AssetComposition::Custom,
            AssetCallbackFlag::Disabled,
        )
        .unwrap_err();

        assert_matches!(err, AssetError::UnsupportedAssetComposition(AssetComposition::Custom));

        Ok(())
    }
}
