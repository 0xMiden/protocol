use alloc::string::ToString;
use core::fmt;

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

mod asset_value;
pub use asset_value::AssetValue;

mod fungible;

pub use fungible::FungibleAsset;

mod nonfungible;

pub use nonfungible::{NonFungibleAsset, NonFungibleAssetDetails};

mod token_symbol;
pub use token_symbol::TokenSymbol;

mod asset_callbacks;
pub use asset_callbacks::AssetCallbacks;

mod asset_composition;
pub use asset_composition::AssetComposition;

mod vault;
pub use vault::{AssetClass, AssetId, AssetIdHash, AssetVault, AssetWitness, PartialVault};

// ASSET
// ================================================================================================

/// Assets are encoded as an [`AssetId`] and an [`AssetValue`], each encodable as one word.
///
/// The [`AssetId`] uniquely identifies the asset and contains the [`AccountId`] of the issuer and
/// the [`AssetClass`], which can further divide a single account's assets into different classes.
/// It also contains the [`AssetComposition`],  which describes how assets compose, meaning whether
/// they can be merged or split. For example, cominbing two fungible assets with the same ID and
/// amounts 3 and 4 into a single one with amount 7 is called "merging". Splitting would be the
/// reverse operation.
///
/// It is impossible to find a collision between two fungible assets issued by different faucets as
/// the faucet ID is part of the asset's ID and the protocol's
/// [`AccountTree`](crate::block::account_tree::AccountTree) guarantees that account IDs are
/// globally unique.
///
/// Assets are generally opaque to the protocol, with the [`FungibleAsset]` being the exception.
/// It is built-in in the sense that the tx kernel knows how to merge and split such assets without
/// requiring a procedure call to the issuing account, which improves performance.
///
/// ## Fungible assets
///
/// All assets carrying [`AssetComposition::Fungible`] are interpreted as a fungible
/// asset, and this composition allows merging and splitting of assets.
///
///
/// - A fungible asset's value layout is: `[amount, 0, 0, 0]`.
/// - A fungible asset's ID layout is: `[0, 0, faucet_id_suffix_and_metadata, faucet_id_prefix]`.
///
/// Where:
/// - `amount` is the [`AssetAmount`] that the asset holds and cannot be greater than
///   [`AssetAmount::MAX`] and thus fits into a felt.
/// - the remaining elements in the value word must be zero.
/// - `faucet_id_prefix` is the prefix of the faucet ID which issues the asset.
/// - `faucet_id_suffix_and_metadata` is the suffix of the faucet ID which issues the asset and the
///   asset metadata, which is the encoding version together with the [`AssetComposition`]. See
///   [`AssetId`] for more details on the ID's layout.
/// - the asset class limbs must be zero, which means two instances of the same fungible asset have
///   the same asset ID and will be merged together when stored in the same account's vault.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Asset {
    id: AssetId,
    value: AssetValue,
}

impl Asset {
    /// Creates an asset from the provided ID and value.
    ///
    /// The value of a fungible asset is validated, see [`FungibleAsset::from_id_and_value`]. The
    /// value of any other asset is opaque to the protocol and therefore not validated.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The asset is fungible and [`FungibleAsset::from_id_and_value`] fails.
    pub fn new(id: AssetId, value: Word) -> Result<Self, AssetError> {
        // An AssetId cannot be constructed with a Custom composition, so only the fungible case
        // needs to be validated here.
        if id.composition().is_fungible() {
            FungibleAsset::from_id_and_value(id, value)?;
        }

        // TODO: Propagate the AssetValue type through the Asset API and beyond.
        Ok(Self { id, value: AssetValue::from_raw(value) })
    }

    /// Creates an asset from the provided ID and value.
    ///
    /// Prefer [`Self::new`] for more type safety.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided ID does not contain a valid faucet ID.
    /// - [`Self::new`] fails.
    pub fn from_id_and_value_words(id: Word, value: Word) -> Result<Self, AssetError> {
        let asset_id = AssetId::try_from(id)?;
        Self::new(asset_id, value)
    }

    /// Returns true if this asset is the same as the specified asset.
    ///
    /// Two assets are defined to be the same if their asset IDs match.
    pub fn is_same(&self, other: &Self) -> bool {
        self.id() == other.id()
    }

    /// Returns true if this asset has [`AssetComposition::Fungible`], `false` otherwise.
    pub fn is_fungible(&self) -> bool {
        self.id.composition().is_fungible()
    }

    /// Returns true if this asset has [`AssetComposition::None`], `false` otherwise.
    pub fn is_non_fungible(&self) -> bool {
        self.id.composition().is_none()
    }

    /// Returns the ID of the faucet that issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        self.id.faucet_id()
    }

    /// Returns the [`AssetId`] which uniquely identifies this asset in the account vault.
    pub fn id(&self) -> AssetId {
        self.id
    }

    /// Returns the [`AssetValue`] of this asset.
    pub fn value(&self) -> AssetValue {
        self.value
    }

    /// Returns the asset's [`AssetId`] encoded to a [`Word`].
    pub fn to_id_word(&self) -> Word {
        self.id().to_word()
    }

    /// Returns the asset's value encoded to a [`Word`].
    pub fn to_value_word(&self) -> Word {
        self.value.as_word()
    }

    /// Returns the asset encoded as elements.
    ///
    /// The first four elements contain the asset ID and the last four elements contain the asset
    /// value.
    pub fn as_elements(&self) -> [Felt; 8] {
        let mut elements = [Felt::ZERO; 8];
        elements[0..4].copy_from_slice(self.to_id_word().as_elements());
        elements[4..8].copy_from_slice(self.to_value_word().as_elements());
        elements
    }

    /// Returns this asset as a [`FungibleAsset`], or `None` if the asset is not a valid fungible
    /// asset.
    pub fn as_fungible(&self) -> Option<FungibleAsset> {
        FungibleAsset::from_id_and_value(self.id, self.to_value_word()).ok()
    }

    /// Returns this asset as a [`FungibleAsset`].
    ///
    /// # Panics
    ///
    /// Panics if the asset is not fungible.
    pub fn unwrap_fungible(&self) -> FungibleAsset {
        self.as_fungible().expect("the asset should be fungible")
    }
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Asset(id: {}, value: {})", self.id, self.value)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Asset {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.id);
        target.write(self.value);
    }

    fn get_size_hint(&self) -> usize {
        self.id.get_size_hint() + self.value.get_size_hint()
    }
}

impl Deserializable for Asset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id: AssetId = source.read()?;
        let value: AssetValue = source.read()?;

        Asset::new(id, value.as_word())
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
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
    use crate::asset::{AssetClass, AssetComposition, AssetId};
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

    /// Returns the metadata byte encoded in an asset ID word.
    pub(super) fn asset_metadata(id: AssetId) -> u8 {
        (id.to_word()[2].as_canonical_u64() & AssetId::METADATA_BYTE_MASK as u64) as u8
    }

    /// Overwrites the metadata byte of the third element of an asset ID word.
    pub(super) fn set_asset_metadata(id: AssetId, byte: u8) -> Word {
        let mut id_word = id.to_word();
        let raw = id_word[2].as_canonical_u64();
        let new_raw = (raw & !(AssetId::METADATA_BYTE_MASK as u64)) | byte as u64;
        id_word[2] =
            Felt::try_from(new_raw).expect("clearing lower bits should produce a valid felt");
        id_word
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
                Asset::from_id_and_value_words(
                    fungible_asset.to_id_word(),
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
                Asset::from_id_and_value_words(
                    non_fungible_asset.to_id_word(),
                    non_fungible_asset.to_value_word()
                )?
            );
        }

        Ok(())
    }

    /// Asserts that every serialized asset leads with the [`AssetComposition`] byte of its
    /// [`AssetId`]. Deserialization of the ID relies on this discriminator.
    #[test]
    fn test_composition_byte_is_serialized_first() {
        let fungible_bytes = FungibleAsset::mock(300).to_bytes();
        assert_eq!(fungible_bytes[0], AssetComposition::Fungible.as_u8());

        let non_fungible_bytes = NonFungibleAsset::mock(&[0xaa, 0xbb]).to_bytes();
        assert_eq!(non_fungible_bytes[0], AssetComposition::None.as_u8());
    }

    /// `Asset::from_id_and_value` must reject a [`AssetComposition::Custom`] asset ID with
    /// `UnsupportedAssetComposition`.
    #[test]
    fn test_from_id_and_value_rejects_custom_composition() -> anyhow::Result<()> {
        let err = AssetId::new(
            AssetClass::default(),
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?,
            AssetComposition::Custom,
        )
        .unwrap_err();

        assert_matches!(err, AssetError::UnsupportedAssetComposition(AssetComposition::Custom));

        Ok(())
    }

    /// Roundtrip an asset with composition `None` through the `Asset` type.
    #[test]
    fn test_opaque_asset_roundtrip() -> anyhow::Result<()> {
        let asset_id = AssetId::new(
            AssetClass::new(Felt::from(1u32), Felt::from(2u32)),
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET.try_into()?,
            AssetComposition::None,
        )?;
        let value = Word::from([7, 8, 9, 10u32]);
        let asset = Asset::new(asset_id, value)?;

        assert_eq!(asset.id(), asset_id);
        assert_eq!(asset.to_value_word(), value);
        assert_eq!(asset, Asset::read_from_bytes(&asset.to_bytes()).unwrap());
        assert_eq!(asset.to_bytes().len(), asset.get_size_hint());
        assert_eq!(asset, Asset::from_id_and_value_words(asset.to_id_word(), value)?);

        Ok(())
    }
}
