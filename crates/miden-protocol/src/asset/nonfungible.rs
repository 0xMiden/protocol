use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use super::vault::AssetVaultKey;
use super::{AccountType, Asset, AssetCallbackFlag, AssetError, Word};
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
    /// An account ID (15 bytes) plus a word (32 bytes) plus a callbacks flag (1 byte).
    pub const SERIALIZED_SIZE: usize =
        AccountId::SERIALIZED_SIZE + Word::SERIALIZED_SIZE + AssetCallbackFlag::SERIALIZED_SIZE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a non-fungible asset created from the specified asset details.
    ///
    /// # Errors
    /// Returns an error if the provided faucet ID is not for a non-fungible asset faucet.
    pub fn new(details: &NonFungibleAssetDetails) -> Result<Self, AssetError> {
        let data_hash = Hasher::hash(details.asset_data());
        Self::from_parts(details.faucet_id(), data_hash)
    }

    /// Return a non-fungible asset created from the specified faucet and using the provided
    /// hash of the asset's data.
    ///
    /// Hash of the asset's data is expected to be computed from the binary representation of the
    /// asset's data.
    ///
    /// # Errors
    /// Returns an error if the provided faucet ID is not for a non-fungible asset faucet.
    pub fn from_parts(faucet_id: AccountId, value: Word) -> Result<Self, AssetError> {
        if !matches!(faucet_id.account_type(), AccountType::NonFungibleFaucet) {
            return Err(AssetError::NonFungibleFaucetIdTypeMismatch(faucet_id));
        }

        Ok(Self {
            faucet_id,
            value,
            callbacks: AssetCallbackFlag::default(),
        })
    }

    /// Creates a non-fungible asset from the provided key and value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided key does not contain a valid faucet ID.
    /// - The provided key's asset ID limbs are not equal to the provided value's first and second
    ///   element.
    /// - The faucet ID is not a non-fungible faucet ID.
    pub fn from_key_value(key: AssetVaultKey, value: Word) -> Result<Self, AssetError> {
        if key.asset_id().suffix() != value[0] || key.asset_id().prefix() != value[1] {
            return Err(AssetError::NonFungibleAssetIdMustMatchValue {
                asset_id: key.asset_id(),
                value,
            });
        }

        let mut asset = Self::from_parts(key.faucet_id(), value)?;
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
    /// - The provided key does not contain a valid faucet ID.
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

        AssetVaultKey::new(asset_id, self.faucet_id, self.callbacks)
            .expect("constructors should ensure account ID is of type non-fungible faucet")
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
        // All assets should serialize their faucet ID at the first position to allow them to be
        // easily distinguishable during deserialization.
        target.write(self.faucet_id());
        target.write(self.value);
        target.write(self.callbacks);
    }

    fn get_size_hint(&self) -> usize {
        self.faucet_id.get_size_hint() + self.value.get_size_hint() + self.callbacks.get_size_hint()
    }
}

impl Deserializable for NonFungibleAsset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let faucet_id: AccountId = source.read()?;

        Self::deserialize_with_faucet_id(faucet_id, source)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

impl NonFungibleAsset {
    /// Deserializes a [`NonFungibleAsset`] from an [`AccountId`] and the remaining data from the
    /// given `source`.
    pub(super) fn deserialize_with_faucet_id<R: ByteReader>(
        faucet_id: AccountId,
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let value: Word = source.read()?;
        let callbacks: AssetCallbackFlag = source.read()?;

        NonFungibleAsset::from_parts(faucet_id, value)
            .map(|asset| asset.with_callbacks(callbacks))
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
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
    ///
    /// # Errors
    /// Returns an error if the provided faucet ID is not for a non-fungible asset faucet.
    pub fn new(faucet_id: AccountId, asset_data: Vec<u8>) -> Result<Self, AssetError> {
        if !matches!(faucet_id.account_type(), AccountType::NonFungibleFaucet) {
            return Err(AssetError::NonFungibleFaucetIdTypeMismatch(faucet_id));
        }

        Ok(Self { faucet_id, asset_data })
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
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1,
    };

    #[test]
    fn fungible_asset_from_key_value_fails_on_invalid_asset_id() -> anyhow::Result<()> {
        let invalid_key = AssetVaultKey::new_native(
            AssetId::new(Felt::from(1u32), Felt::from(2u32)),
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET.try_into()?,
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
            let details = NonFungibleAssetDetails::new(account_id, vec![1, 2, 3]).unwrap();
            let non_fungible_asset = NonFungibleAsset::new(&details).unwrap();
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

        let account = AccountId::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET).unwrap();
        let details = NonFungibleAssetDetails::new(account, vec![4, 5, 6, 7]).unwrap();
        let asset = NonFungibleAsset::new(&details).unwrap();
        let mut asset_bytes = asset.to_bytes();

        let fungible_faucet_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET).unwrap();

        // Set invalid faucet ID.
        asset_bytes[0..AccountId::SERIALIZED_SIZE].copy_from_slice(&fungible_faucet_id.to_bytes());

        let err = NonFungibleAsset::read_from_bytes(&asset_bytes).unwrap_err();
        assert_matches!(err, DeserializationError::InvalidValue(msg) if msg.contains("must be of type NonFungibleFaucet"));

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
