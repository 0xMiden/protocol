use core::fmt;

use super::vault::AssetId;
use super::{Asset, AssetAmount, AssetComposition, AssetError, Word};
use crate::Felt;
use crate::account::{AccountId, AssetCallbackFlag};
use crate::asset::AssetClass;

// FUNGIBLE ASSET
// ================================================================================================
/// A fungible asset.
///
/// A fungible asset consists of a faucet ID of the faucet which issued the asset as well as the
/// asset amount. Asset amount is guaranteed to be 2^63 - 1 or smaller.
///
/// Whether the asset triggers callbacks to the faucet is an immutable property of the faucet's
/// [`AccountId`], see [`AccountId::asset_callback_flag`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FungibleAsset {
    faucet_id: AccountId,
    amount: AssetAmount,
}

impl FungibleAsset {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// Specifies the maximum amount a fungible asset can represent.
    ///
    /// This number was chosen so that it can be represented as a positive and negative number in a
    /// field element. See `account_update.masm` for more details on how this number was chosen.
    pub const MAX_AMOUNT: AssetAmount = AssetAmount::MAX;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a fungible asset instantiated with the provided faucet ID and amount.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided amount is greater than [`FungibleAsset::MAX_AMOUNT`].
    pub fn new(faucet_id: AccountId, amount: u64) -> Result<Self, AssetError> {
        // TODO: Take AssetAmount as input, then make the function infallible.
        let amount = AssetAmount::new(amount)?;

        Ok(Self { faucet_id, amount })
    }

    /// Creates a fungible asset from the provided ID and value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided ID does not contain a valid faucet ID.
    /// - The provided ID does not have [`AssetComposition::Fungible`] set.
    /// - The provided ID's asset class limbs are not zero.
    /// - The provided value's amount is greater than [`FungibleAsset::MAX_AMOUNT`] or its three
    ///   most significant elements are not zero.
    pub fn from_id_and_value(id: AssetId, value: Word) -> Result<Self, AssetError> {
        if !id.composition().is_fungible() {
            return Err(AssetError::AssetCompositionMismatch {
                faucet_id: id.faucet_id(),
                expected: AssetComposition::Fungible,
                actual: id.composition(),
            });
        }

        if !id.asset_class().is_empty() {
            return Err(AssetError::FungibleAssetClassMustBeZero(id.asset_class()));
        }

        if value[1] != Felt::ZERO || value[2] != Felt::ZERO || value[3] != Felt::ZERO {
            return Err(AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(value));
        }

        Self::new(id.faucet_id(), value[0].as_canonical_u64())
    }

    /// Creates a fungible asset from the provided ID and value.
    ///
    /// Prefer [`Self::from_id_and_value`] for more type safety.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`Self::from_id_and_value`] fails.
    pub fn from_id_and_value_words(id: Word, value: Word) -> Result<Self, AssetError> {
        let asset_id = AssetId::try_from(id)?;
        Self::from_id_and_value(asset_id, value)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Return ID of the faucet which issued this asset.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// Returns the [`AssetCallbackFlag`] of the faucet which issued this asset.
    pub fn callbacks(&self) -> AssetCallbackFlag {
        self.faucet_id.asset_callback_flag()
    }

    /// Returns the amount of this asset.
    pub fn amount(&self) -> AssetAmount {
        self.amount
    }

    /// Returns true if this and the other asset were issued from the same faucet.
    pub fn is_same(&self, other: &Self) -> bool {
        self.id() == other.id()
    }

    /// Returns the [`AssetId`] which uniquely identifies this asset in the account vault.
    pub fn id(&self) -> AssetId {
        AssetId::new(AssetClass::default(), self.faucet_id, AssetComposition::Fungible)
            .expect("default asset class should be valid for fungible composition")
    }

    /// Returns the asset's [`AssetId`] encoded to a [`Word`].
    pub fn to_id_word(&self) -> Word {
        self.id().to_word()
    }

    /// Returns the asset's value encoded to a [`Word`].
    pub fn to_value_word(&self) -> Word {
        self.amount.to_word()
    }

    // OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Adds two fungible assets together and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets do not have the same asset ID (i.e. different faucet).
    /// - The total value of assets is greater than or equal to 2^63.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Result<Self, AssetError> {
        if !self.is_same(&other) {
            return Err(AssetError::FungibleAssetInconsistentIds {
                original_id: self.id(),
                other_id: other.id(),
            });
        }

        let amount = (self.amount + other.amount)?;

        Ok(Self { faucet_id: self.faucet_id, amount })
    }

    /// Subtracts a fungible asset from another and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The assets do not have the same asset ID (i.e. different faucet).
    /// - The final amount would be negative.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Self) -> Result<Self, AssetError> {
        if !self.is_same(&other) {
            return Err(AssetError::FungibleAssetInconsistentIds {
                original_id: self.id(),
                other_id: other.id(),
            });
        }

        let amount = (self.amount - other.amount)?;

        Ok(FungibleAsset { faucet_id: self.faucet_id, amount })
    }
}

impl From<FungibleAsset> for Asset {
    fn from(asset: FungibleAsset) -> Self {
        Asset::new(asset.id(), asset.to_value_word())
            .expect("fungible asset should be a valid asset")
    }
}

impl fmt::Display for FungibleAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Replace with hex representation?
        write!(f, "{self:?}")
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
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET;

    #[test]
    fn fungible_asset_from_id_and_value_words_fails_on_invalid_composition() -> anyhow::Result<()> {
        let asset_id = set_asset_metadata(
            FungibleAsset::mock(25).id(),
            AssetId::encode_metadata(AssetComposition::None),
        );

        let err = FungibleAsset::from_id_and_value_words(
            asset_id,
            FungibleAsset::mock(5).to_value_word(),
        )
        .unwrap_err();
        assert_matches!(err, AssetError::AssetCompositionMismatch {
                faucet_id: _, expected, actual: _
            } => {
                assert_eq!(expected, AssetComposition::Fungible);
        });

        Ok(())
    }

    #[test]
    fn fungible_asset_from_id_and_value_words_fails_on_invalid_asset_class() -> anyhow::Result<()> {
        let faucet_id: AccountId = ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET.try_into()?;
        let mut asset_id =
            AssetId::new(AssetClass::default(), faucet_id, AssetComposition::Fungible)?.to_word();
        asset_id[0] = Felt::from(1u32);
        asset_id[1] = Felt::from(2u32);

        let err = FungibleAsset::from_id_and_value_words(
            asset_id,
            FungibleAsset::mock(5).to_value_word(),
        )
        .unwrap_err();
        assert_matches!(err, AssetError::FungibleAssetClassMustBeZero(_));

        Ok(())
    }

    #[test]
    fn fungible_asset_from_id_and_value_fails_on_invalid_value() -> anyhow::Result<()> {
        let asset = FungibleAsset::mock(42);
        let mut invalid_value = asset.to_value_word();
        invalid_value[2] = Felt::from(5u32);

        let err = FungibleAsset::from_id_and_value(asset.id(), invalid_value).unwrap_err();
        assert_matches!(err, AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_));

        Ok(())
    }

    #[test]
    fn test_asset_id_for_fungible_asset() {
        let asset = FungibleAsset::mock(34);

        assert_eq!(asset.id().faucet_id(), FungibleAsset::mock_issuer());
        assert_eq!(asset.id().asset_class().prefix().as_canonical_u64(), 0);
        assert_eq!(asset.id().asset_class().suffix().as_canonical_u64(), 0);
    }
}
