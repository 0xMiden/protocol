use alloc::string::ToString;
use core::fmt;

use super::vault::AssetVaultKey;
use super::{
    AccountType,
    Asset,
    AssetAmount,
    AssetCallbackFlag,
    AssetComposition,
    AssetError,
    Word,
};
use crate::Felt;
use crate::account::AccountId;
use crate::asset::AssetId;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// FUNGIBLE ASSET
// ================================================================================================
/// A fungible asset.
///
/// A fungible asset consists of a faucet ID of the faucet which issued the asset as well as the
/// asset amount. Asset amount is guaranteed to be 2^63 - 1 or smaller.
///
/// The fungible asset can have callbacks to the faucet enabled or disabled, depending on
/// [`AssetCallbackFlag`]. See [`AssetCallbacks`](crate::asset::AssetCallbacks) for more details.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FungibleAsset {
    faucet_id: AccountId,
    amount: AssetAmount,
    callbacks: AssetCallbackFlag,
}

impl FungibleAsset {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// Specifies the maximum amount a fungible asset can represent.
    ///
    /// This number was chosen so that it can be represented as a positive and negative number in a
    /// field element. See `account_delta.masm` for more details on how this number was chosen.
    pub const MAX_AMOUNT: AssetAmount = AssetAmount::MAX;

    /// The serialized size of a [`FungibleAsset`] in bytes.
    ///
    /// A composition byte (u8) plus an account ID (15 bytes) plus an amount (u64) plus a
    /// callbacks flag (u8).
    pub const SERIALIZED_SIZE: usize = AssetComposition::SERIALIZED_SIZE
        + AccountId::SERIALIZED_SIZE
        + core::mem::size_of::<u64>()
        + AssetCallbackFlag::SERIALIZED_SIZE;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a fungible asset instantiated with the provided faucet ID and amount.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The faucet ID is not a valid fungible faucet ID.
    /// - The provided amount is greater than [`FungibleAsset::MAX_AMOUNT`].
    pub fn new(faucet_id: AccountId, amount: u64) -> Result<Self, AssetError> {
        if !matches!(faucet_id.account_type(), AccountType::FungibleFaucet) {
            return Err(AssetError::FungibleFaucetIdTypeMismatch(faucet_id));
        }

        let amount = AssetAmount::new(amount)?;

        Ok(Self {
            faucet_id,
            amount,
            callbacks: AssetCallbackFlag::default(),
        })
    }

    /// Creates a fungible asset from the provided key and value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided key does not contain a valid faucet ID.
    /// - The provided key's does not have [`AssetComposition::Fungible`] set.
    /// - The provided key's asset ID limbs are not zero.
    /// - The provided value's amount is greater than [`FungibleAsset::MAX_AMOUNT`] or its three
    ///   most significant elements are not zero.
    pub fn from_key_value(key: AssetVaultKey, value: Word) -> Result<Self, AssetError> {
        if !key.composition().is_fungible() {
            return Err(AssetError::AssetCompositionMismatch {
                faucet_id: key.faucet_id(),
                expected: AssetComposition::Fungible,
                actual: key.composition(),
            });
        }

        if !key.asset_id().is_empty() {
            return Err(AssetError::FungibleAssetIdMustBeZero(key.asset_id()));
        }

        if value[1] != Felt::ZERO || value[2] != Felt::ZERO || value[3] != Felt::ZERO {
            return Err(AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(value));
        }

        let mut asset = Self::new(key.faucet_id(), value[0].as_canonical_u64())?;
        asset.callbacks = key.callback_flag();

        Ok(asset)
    }

    /// Creates a fungible asset from the provided key and value.
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

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Return ID of the faucet which issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the amount of this asset.
    pub fn amount(&self) -> AssetAmount {
        self.amount
    }

    /// Returns true if this and the other asset were issued from the same faucet.
    pub fn is_same(&self, other: &Self) -> bool {
        self.vault_key() == other.vault_key()
    }

    /// Returns the [`AssetCallbackFlag`] of this asset.
    pub fn callbacks(&self) -> AssetCallbackFlag {
        self.callbacks
    }

    /// Returns the key which is used to store this asset in the account vault.
    pub fn vault_key(&self) -> AssetVaultKey {
        AssetVaultKey::new(
            AssetId::default(),
            self.faucet_id,
            AssetComposition::Fungible,
            self.callbacks,
        )
        .expect("faucet ID should be of type fungible")
    }

    /// Returns the asset's key encoded to a [`Word`].
    pub fn to_key_word(&self) -> Word {
        self.vault_key().to_word()
    }

    /// Returns the asset's value encoded to a [`Word`].
    pub fn to_value_word(&self) -> Word {
        Word::new([Felt::from(self.amount), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    // OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Adds two fungible assets together and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets do not have the same vault key (i.e. different faucet or callback flags).
    /// - The total value of assets is greater than or equal to 2^63.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Result<Self, AssetError> {
        if !self.is_same(&other) {
            return Err(AssetError::FungibleAssetInconsistentVaultKeys {
                original_key: self.vault_key(),
                other_key: other.vault_key(),
            });
        }

        let amount = (self.amount + other.amount)?;

        Ok(Self {
            faucet_id: self.faucet_id,
            amount,
            callbacks: self.callbacks,
        })
    }

    /// Subtracts a fungible asset from another and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets do not have the same vault key (i.e. different faucet or callback flags).
    /// - The final amount would be negative.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Self) -> Result<Self, AssetError> {
        if !self.is_same(&other) {
            return Err(AssetError::FungibleAssetInconsistentVaultKeys {
                original_key: self.vault_key(),
                other_key: other.vault_key(),
            });
        }

        let amount = (self.amount - other.amount)?;

        Ok(FungibleAsset {
            faucet_id: self.faucet_id,
            amount,
            callbacks: self.callbacks,
        })
    }
}

impl From<FungibleAsset> for Asset {
    fn from(asset: FungibleAsset) -> Self {
        Asset::Fungible(asset)
    }
}

impl fmt::Display for FungibleAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Replace with hex representation?
        write!(f, "{self:?}")
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for FungibleAsset {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Lead with the asset composition byte to distinguish asset types on the wire.
        target.write(AssetComposition::Fungible);
        target.write(self.faucet_id);
        target.write(self.amount.as_u64());
        target.write(self.callbacks);
    }

    fn get_size_hint(&self) -> usize {
        AssetComposition::SERIALIZED_SIZE
            + self.faucet_id.get_size_hint()
            + self.amount.as_u64().get_size_hint()
            + self.callbacks.get_size_hint()
    }
}

impl Deserializable for FungibleAsset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let composition: AssetComposition = source.read()?;
        if !composition.is_fungible() {
            return Err(DeserializationError::InvalidValue(format!(
                "expected fungible asset composition but found {composition:?}"
            )));
        }
        FungibleAsset::deserialize_body(source)
    }
}

impl FungibleAsset {
    /// Reads the remaining body of a fungible asset, after the leading composition byte has
    /// already been consumed.
    pub(super) fn deserialize_body<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let faucet_id: AccountId = source.read()?;
        let amount: u64 = source.read()?;
        let callbacks = source.read()?;

        let asset = FungibleAsset::new(faucet_id, amount)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?
            .with_callbacks(callbacks);

        Ok(asset)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::account::AccountId;
    use crate::asset::tests::set_asset_metadata;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    };

    #[test]
    fn fungible_asset_from_key_value_words_fails_on_invalid_composition() -> anyhow::Result<()> {
        let asset_key =
            set_asset_metadata(FungibleAsset::mock(25).vault_key(), AssetComposition::None.as_u8());

        let err =
            FungibleAsset::from_key_value_words(asset_key, FungibleAsset::mock(5).to_value_word())
                .unwrap_err();
        assert_matches!(err, AssetError::AssetCompositionMismatch {
                faucet_id: _, expected, actual: _
            } => {
                assert_eq!(expected, AssetComposition::Fungible);
        });

        Ok(())
    }

    #[test]
    fn fungible_asset_from_key_value_words_fails_on_invalid_asset_id() -> anyhow::Result<()> {
        let faucet_id: AccountId = ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?;
        let mut asset_key = AssetVaultKey::new(
            AssetId::default(),
            faucet_id,
            AssetComposition::Fungible,
            AssetCallbackFlag::Disabled,
        )?
        .to_word();
        asset_key[0] = Felt::from(1u32);
        asset_key[1] = Felt::from(2u32);

        let err =
            FungibleAsset::from_key_value_words(asset_key, FungibleAsset::mock(5).to_value_word())
                .unwrap_err();
        assert_matches!(err, AssetError::FungibleAssetIdMustBeZero(_));

        Ok(())
    }

    #[test]
    fn fungible_asset_from_key_value_fails_on_invalid_value() -> anyhow::Result<()> {
        let asset = FungibleAsset::mock(42);
        let mut invalid_value = asset.to_value_word();
        invalid_value[2] = Felt::from(5u32);

        let err = FungibleAsset::from_key_value(asset.vault_key(), invalid_value).unwrap_err();
        assert_matches!(err, AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_));

        Ok(())
    }

    #[test]
    fn test_fungible_asset_serde() -> anyhow::Result<()> {
        for fungible_account_id in [
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
        ] {
            let account_id = AccountId::try_from(fungible_account_id).unwrap();
            let fungible_asset = FungibleAsset::new(account_id, 10).unwrap();
            assert_eq!(
                fungible_asset,
                FungibleAsset::read_from_bytes(&fungible_asset.to_bytes()).unwrap()
            );
            assert_eq!(fungible_asset.to_bytes().len(), fungible_asset.get_size_hint());

            assert_eq!(
                fungible_asset,
                FungibleAsset::from_key_value_words(
                    fungible_asset.to_key_word(),
                    fungible_asset.to_value_word()
                )?
            )
        }

        let account_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3).unwrap();
        let asset = FungibleAsset::new(account_id, 50).unwrap();
        let mut asset_bytes = asset.to_bytes();
        assert_eq!(asset_bytes.len(), asset.get_size_hint());
        assert_eq!(asset.get_size_hint(), FungibleAsset::SERIALIZED_SIZE);

        let non_fungible_faucet_id =
            AccountId::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET).unwrap();

        // Overwrite the faucet ID with a non-fungible faucet ID. The composition byte at offset 0
        // still declares the asset as fungible, so deserialization should reject it once the inner
        // check runs.
        let faucet_id_start = AssetComposition::SERIALIZED_SIZE;
        let faucet_id_end = faucet_id_start + AccountId::SERIALIZED_SIZE;
        asset_bytes[faucet_id_start..faucet_id_end]
            .copy_from_slice(&non_fungible_faucet_id.to_bytes());
        let err = FungibleAsset::read_from_bytes(&asset_bytes).unwrap_err();
        assert!(matches!(err, DeserializationError::InvalidValue(_)));

        Ok(())
    }

    #[test]
    fn test_vault_key_for_fungible_asset() {
        let asset = FungibleAsset::mock(34);

        assert_eq!(asset.vault_key().faucet_id(), FungibleAsset::mock_issuer());
        assert_eq!(asset.vault_key().asset_id().prefix().as_canonical_u64(), 0);
        assert_eq!(asset.vault_key().asset_id().suffix().as_canonical_u64(), 0);
    }
}
