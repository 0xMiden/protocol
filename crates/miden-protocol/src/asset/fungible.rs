use alloc::string::ToString;
use core::fmt;

use super::vault::AssetVaultKey;
use super::{AccountType, Asset, AssetError, Word};
use crate::account::AccountId;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, FieldElement};

// FUNGIBLE ASSET
// ================================================================================================
/// A fungible asset.
///
/// A fungible asset consists of a faucet ID of the faucet which issued the asset as well as the
/// asset amount. Asset amount is guaranteed to be 2^63 - 1 or smaller.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FungibleAsset {
    faucet_id: AccountId,
    amount: u64,
}

impl FungibleAsset {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// Specifies the maximum amount a fungible asset can represent.
    ///
    /// This number was chosen so that it can be represented as a positive and negative number in a
    /// field element. See `account_delta.masm` for more details on how this number was chosen.
    pub const MAX_AMOUNT: u64 = 2u64.pow(63) - 2u64.pow(31);

    /// The serialized size of a [`FungibleAsset`] in bytes.
    ///
    /// An account ID (15 bytes) plus an amount (u64).
    pub const SERIALIZED_SIZE: usize = AccountId::SERIALIZED_SIZE + core::mem::size_of::<u64>();

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

        if amount > Self::MAX_AMOUNT {
            return Err(AssetError::FungibleAssetAmountTooBig(amount));
        }

        Ok(Self { faucet_id, amount })
    }

    /// Creates a fungible asset from the provided key and value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided key does not contain a valid faucet ID.
    /// - The provided key's asset ID limbs are not zero.
    /// - The faucet ID is not a fungible faucet ID.
    /// - The provided value's amount is greater than [`FungibleAsset::MAX_AMOUNT`] or its three
    ///   most significant elements are not zero.
    pub fn from_key_value(key: AssetVaultKey, value: Word) -> Result<Self, AssetError> {
        if !key.asset_id().is_empty() {
            return Err(AssetError::FungibleAssetIdMustBeZero(key.asset_id()));
        }

        if value[1] != Felt::ZERO || value[2] != Felt::ZERO || value[3] != Felt::ZERO {
            return Err(AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(value));
        }

        Self::new(key.faucet_id(), value[0].as_int())
    }

    /// Creates a fungible asset from the provided key and value.
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

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Return ID of the faucet which issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the amount of this asset.
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns true if this and the other assets were issued from the same faucet.
    pub fn is_from_same_faucet(&self, other: &Self) -> bool {
        self.faucet_id == other.faucet_id
    }

    /// Returns the key which is used to store this asset in the account vault.
    pub fn vault_key(&self) -> AssetVaultKey {
        AssetVaultKey::new_fungible(self.faucet_id).expect("faucet ID should be of type fungible")
    }

    /// Returns the asset's key encoded to a [`Word`].
    pub fn to_key_word(&self) -> Word {
        self.vault_key().to_word()
    }

    /// Returns the asset's value encoded to a [`Word`].
    pub fn to_value_word(&self) -> Word {
        Word::new([
            Felt::try_from(self.amount)
                .expect("fungible asset should only allow amounts that fit into a felt"),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ])
    }

    // OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Adds two fungible assets together and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets were not issued by the same faucet.
    /// - The total value of assets is greater than or equal to 2^63.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Result<Self, AssetError> {
        if self.faucet_id != other.faucet_id {
            return Err(AssetError::FungibleAssetInconsistentFaucetIds {
                original_issuer: self.faucet_id,
                other_issuer: other.faucet_id,
            });
        }

        let amount = self
            .amount
            .checked_add(other.amount)
            .expect("even MAX_AMOUNT + MAX_AMOUNT should not overflow u64");
        if amount > Self::MAX_AMOUNT {
            return Err(AssetError::FungibleAssetAmountTooBig(amount));
        }

        Ok(Self { faucet_id: self.faucet_id, amount })
    }

    /// Subtracts a fungible asset from another and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets were not issued by the same faucet.
    /// - The final amount would be negative.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Self) -> Result<Self, AssetError> {
        if self.faucet_id != other.faucet_id {
            return Err(AssetError::FungibleAssetInconsistentFaucetIds {
                original_issuer: self.faucet_id,
                other_issuer: other.faucet_id,
            });
        }

        let amount = self.amount.checked_sub(other.amount).ok_or(
            AssetError::FungibleAssetAmountNotSufficient {
                minuend: self.amount,
                subtrahend: other.amount,
            },
        )?;

        Ok(FungibleAsset { faucet_id: self.faucet_id, amount })
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
        // All assets should serialize their faucet ID at the first position to allow them to be
        // distinguishable during deserialization.
        target.write(self.faucet_id);
        target.write(self.amount);
    }

    fn get_size_hint(&self) -> usize {
        self.faucet_id.get_size_hint() + self.amount.get_size_hint()
    }
}

impl Deserializable for FungibleAsset {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let faucet_id: AccountId = source.read()?;
        FungibleAsset::deserialize_with_faucet_id(faucet_id, source)
    }
}

impl FungibleAsset {
    /// Deserializes a [`FungibleAsset`] from an [`AccountId`] and the remaining data from the given
    /// `source`.
    pub(super) fn deserialize_with_faucet_id<R: ByteReader>(
        faucet_id: AccountId,
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let amount: u64 = source.read()?;
        FungibleAsset::new(faucet_id, amount)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::account::AccountId;
    use crate::asset::AssetId;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
    };

    #[test]
    fn fungible_asset_from_key_value_fails_on_invalid_asset_id() -> anyhow::Result<()> {
        let invalid_key = AssetVaultKey::new(
            AssetId::new(1u32.into(), 2u32.into()),
            ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?,
        )?;

        let err =
            FungibleAsset::from_key_value(invalid_key, FungibleAsset::mock(5).to_value_word())
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

        // Set invalid Faucet ID.
        asset_bytes[0..15].copy_from_slice(&non_fungible_faucet_id.to_bytes());
        let err = FungibleAsset::read_from_bytes(&asset_bytes).unwrap_err();
        assert!(matches!(err, DeserializationError::InvalidValue(_)));

        Ok(())
    }

    #[test]
    fn test_vault_key_for_fungible_asset() {
        let asset = FungibleAsset::mock(34);

        assert_eq!(asset.vault_key().faucet_id(), FungibleAsset::mock_issuer());
        assert_eq!(asset.vault_key().asset_id().prefix().as_int(), 0);
        assert_eq!(asset.vault_key().asset_id().suffix().as_int(), 0);
    }
}
