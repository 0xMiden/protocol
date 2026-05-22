use alloc::vec::Vec;
use core::fmt;

use super::vault::AssetVaultKey;
use super::{Asset, AssetCallbackFlag, AssetComposition, AssetError, Word};
use crate::Hasher;
use crate::account::AccountId;
use crate::asset::vault::AssetId;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// NON-FUNGIBLE ASSET
// ================================================================================================

/// A commitment to a non-fungible asset.
///
/// See [`Asset`] for details on how it is constructed.
///
/// [`NonFungibleAsset`] itself does not contain the actual asset data. The container for this data
/// is [`NonFungibleAssetDetails`].
///
/// The non-fungible asset can have callbacks to the faucet enabled or disabled, depending on
/// [`AssetCallbackFlag`]. See [`AssetCallbacks`](crate::asset::AssetCallbacks) for more details.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NonFungibleAsset {
    faucet_id: AccountId,
    value: Word,
    callbacks: AssetCallbackFlag,
}

impl NonFungibleAsset {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The serialized size of a [`NonFungibleAsset`] in bytes.
    ///
    /// A composition byte (u8) plus an account ID (15 bytes) plus a word (32 bytes) plus a
    /// callbacks flag (1 byte).
    pub const SERIALIZED_SIZE: usize = AssetComposition::SERIALIZED_SIZE
        + AccountId::SERIALIZED_SIZE
        + Word::SERIALIZED_SIZE
        + AssetCallbackFlag::SERIALIZED_SIZE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a non-fungible asset created from the specified asset details.
    pub fn new(details: &NonFungibleAssetDetails) -> Self {
        let data_hash = Hasher::hash(details.asset_data());
        Self::from_parts(details.faucet_id(), data_hash)
    }

    /// Return a non-fungible asset created from the specified faucet and using the provided
    /// hash of the asset's data.
    ///
    /// Hash of the asset's data is expected to be computed from the binary representation of the
    /// asset's data.
    pub fn from_parts(faucet_id: AccountId, value: Word) -> Self {
        Self {
            faucet_id,
            value,
            callbacks: AssetCallbackFlag::default(),
        }
    }

    /// Creates a non-fungible asset from the provided key and value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided key does not have [`AssetComposition::None`] set.
    /// - The provided key's asset ID limbs are not equal to the provided value's first and second
    ///   element.
    /// - The faucet ID is not a non-fungible faucet ID.
    pub fn from_key_value(key: AssetVaultKey, value: Word) -> Result<Self, AssetError> {
        if !key.composition().is_none() {
            return Err(AssetError::AssetCompositionMismatch {
                faucet_id: key.faucet_id(),
                expected: AssetComposition::None,
                actual: key.composition(),
            });
        }

        if key.asset_id().suffix() != value[0] || key.asset_id().prefix() != value[1] {
            return Err(AssetError::NonFungibleAssetIdMustMatchValue {
                asset_id: key.asset_id(),
                value,
            });
        }

        let mut asset = Self::from_parts(key.faucet_id(), value);
        asset.callbacks = key.callback_flag();

        Ok(asset)
    }

    /// Creates a non-fungible asset from the provided key and value.
    ///
    /// Prefer [`Self::from_key_value`] for more type safety.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`Self::from_key_value`] fails.
    pub fn from_key_value_words(key: Word, value: Word) -> Result<Self, AssetError> {
        let vault_key = AssetVaultKey::try_from(key)?;
        Self::from_key_value(vault_key, value)
    }

    /// Returns a copy of this asset with the given [`AssetCallbackFlag`].
    pub fn with_callbacks(mut self, callbacks: AssetCallbackFlag) -> Self {
        self.callbacks = callbacks;
        self
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the vault key of the [`NonFungibleAsset`].
    ///
    /// See [`Asset`] docs for details on the key.
    pub fn vault_key(&self) -> AssetVaultKey {
        let asset_id_suffix = self.value[0];
        let asset_id_prefix = self.value[1];
        let asset_id = AssetId::new(asset_id_suffix, asset_id_prefix);

        AssetVaultKey::new(asset_id, self.faucet_id, AssetComposition::None, self.callbacks)
            .expect("non-fungible composition is always valid")
    }

    /// Returns the ID of the faucet which issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the [`AssetCallbackFlag`] of this asset.
    pub fn callbacks(&self) -> AssetCallbackFlag {
        self.callbacks
    }

    /// Returns the asset's key encoded to a [`Word`].
    pub fn to_key_word(&self) -> Word {
        self.vault_key().to_word()
    }

    /// Returns the asset's value encoded to a [`Word`].
    pub fn to_value_word(&self) -> Word {
        self.value
    }
}

impl fmt::Display for NonFungibleAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Replace with hex representation?
        write!(f, "{self:?}")
    }
}

impl From<NonFungibleAsset> for Asset {
    fn from(asset: NonFungibleAsset) -> Self {
        Asset::NonFungible(asset)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NonFungibleAsset {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Lead with the asset composition byte to distinguish asset types on the wire.
        target.write(AssetComposition::None);
        target.write(self.faucet_id());
        target.write(self.value);
        target.write(self.callbacks);
    }

    fn get_size_hint(&self) -> usize {
        AssetComposition::SERIALIZED_SIZE
            + self.faucet_id.get_size_hint()
            + self.value.get_size_hint()
            + self.callbacks.get_size_hint()
    }
}

impl Deserializable for NonFungibleAsset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let composition: AssetComposition = source.read()?;
        if !composition.is_none() {
            return Err(DeserializationError::InvalidValue(format!(
                "expected non-fungible asset composition but found {composition:?}"
            )));
        }
        NonFungibleAsset::deserialize_body(source)
    }
}

impl NonFungibleAsset {
    /// Reads the remaining body of a non-fungible asset, after the leading composition byte has
    /// already been consumed.
    pub(super) fn deserialize_body<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let faucet_id: AccountId = source.read()?;
        let value: Word = source.read()?;
        let callbacks: AssetCallbackFlag = source.read()?;

        Ok(NonFungibleAsset::from_parts(faucet_id, value).with_callbacks(callbacks))
    }
}

// NON-FUNGIBLE ASSET DETAILS
// ================================================================================================

/// Details about a non-fungible asset.
///
/// Unlike [NonFungibleAsset] struct, this struct contains full details of a non-fungible asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonFungibleAssetDetails {
    faucet_id: AccountId,
    asset_data: Vec<u8>,
}

impl NonFungibleAssetDetails {
    /// Returns asset details instantiated from the specified faucet ID and asset data.
    pub fn new(faucet_id: AccountId, asset_data: Vec<u8>) -> Self {
        Self { faucet_id, asset_data }
    }

    /// Returns ID of the faucet which issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns asset data in binary format.
    pub fn asset_data(&self) -> &[u8] {
        &self.asset_data
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::Felt;
    use crate::account::AccountId;
    use crate::asset::FungibleAsset;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    };

    #[test]
    fn non_fungible_asset_from_key_value_words_fails_on_invalid_composition() -> anyhow::Result<()>
    {
        // Use a fungible asset's key-value words where the the composition is set to `Fungible`.
        let asset = FungibleAsset::mock(20);

        let err =
            NonFungibleAsset::from_key_value_words(asset.to_key_word(), asset.to_value_word())
                .unwrap_err();
        assert_matches!(err, AssetError::AssetCompositionMismatch {
                faucet_id: _, expected, actual,
            } => {
                assert_eq!(actual, AssetComposition::Fungible);
                assert_eq!(expected, AssetComposition::None);
        });

        Ok(())
    }

    #[test]
    fn fungible_asset_from_key_value_fails_on_invalid_asset_id() -> anyhow::Result<()> {
        let invalid_key = AssetVaultKey::new(
            AssetId::new(Felt::from(1u32), Felt::from(2u32)),
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET.try_into()?,
            AssetComposition::None,
            AssetCallbackFlag::Disabled,
        )?;
        let err =
            NonFungibleAsset::from_key_value(invalid_key, Word::from([4, 5, 6, 7u32])).unwrap_err();

        assert_matches!(err, AssetError::NonFungibleAssetIdMustMatchValue { .. });

        Ok(())
    }

    #[test]
    fn test_non_fungible_asset_serde() -> anyhow::Result<()> {
        for non_fungible_account_id in [
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
        ] {
            let account_id = AccountId::try_from(non_fungible_account_id).unwrap();
            let details = NonFungibleAssetDetails::new(account_id, vec![1, 2, 3]);
            let non_fungible_asset = NonFungibleAsset::new(&details);
            assert_eq!(
                non_fungible_asset,
                NonFungibleAsset::read_from_bytes(&non_fungible_asset.to_bytes()).unwrap()
            );
            assert_eq!(non_fungible_asset.to_bytes().len(), non_fungible_asset.get_size_hint());

            assert_eq!(
                non_fungible_asset,
                NonFungibleAsset::from_key_value_words(
                    non_fungible_asset.to_key_word(),
                    non_fungible_asset.to_value_word()
                )?
            )
        }

        let fungible_asset = FungibleAsset::mock(42);
        let err = NonFungibleAsset::read_from_bytes(&fungible_asset.to_bytes()).unwrap_err();
        assert_matches!(err, DeserializationError::InvalidValue(msg) => {
            assert!(msg.contains("expected non-fungible asset composition but found Fungible"));
        });

        Ok(())
    }

    #[test]
    fn test_vault_key_for_non_fungible_asset() {
        let asset = NonFungibleAsset::mock(&[42]);

        assert_eq!(asset.vault_key().faucet_id(), NonFungibleAsset::mock_issuer());
        assert_eq!(asset.vault_key().asset_id().suffix(), asset.to_value_word()[0]);
        assert_eq!(asset.vault_key().asset_id().prefix(), asset.to_value_word()[1]);
    }
}
