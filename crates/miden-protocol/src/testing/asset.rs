use rand::Rng;
use rand::distr::StandardUniform;

use crate::account::{AccountId, AccountIdPrefix, AccountType};
use crate::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use crate::errors::AssetError;
use crate::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
};

/// Builder for an `NonFungibleAssetDetails`, the builder can be configured and used multiplied
/// times.
#[derive(Debug, Clone)]
pub struct NonFungibleAssetDetailsBuilder<T> {
    faucet_id: AccountIdPrefix,
    rng: T,
}

/// Builder for an `FungibleAsset`, the builder can be configured and used multiplied times.
#[derive(Debug, Clone)]
pub struct FungibleAssetBuilder {
    faucet_id: AccountId,
    amount: u64,
}

impl<T: Rng> NonFungibleAssetDetailsBuilder<T> {
    pub fn new(faucet_id: AccountIdPrefix, rng: T) -> Result<Self, AssetError> {
        if !matches!(faucet_id.account_type(), AccountType::NonFungibleFaucet) {
            return Err(AssetError::NonFungibleFaucetIdTypeMismatch(faucet_id));
        }

        Ok(Self { faucet_id, rng })
    }

    pub fn build(&mut self) -> Result<NonFungibleAssetDetails, AssetError> {
        let data = (&mut self.rng).sample_iter(StandardUniform).take(5).collect();
        NonFungibleAssetDetails::new(self.faucet_id, data)
    }
}

/// Builder for an `NonFungibleAsset`, the builder can be configured and used multiplied times.
#[derive(Debug, Clone)]
pub struct NonFungibleAssetBuilder<T> {
    details_builder: NonFungibleAssetDetailsBuilder<T>,
}

impl<T: Rng> NonFungibleAssetBuilder<T> {
    pub fn new(faucet_id: AccountIdPrefix, rng: T) -> Result<Self, AssetError> {
        let details_builder = NonFungibleAssetDetailsBuilder::new(faucet_id, rng)?;
        Ok(Self { details_builder })
    }

    pub fn build(&mut self) -> Result<NonFungibleAsset, AssetError> {
        let details = self.details_builder.build()?;
        NonFungibleAsset::new(&details)
    }
}

impl FungibleAssetBuilder {
    pub const DEFAULT_AMOUNT: u64 = 10;

    pub fn new(faucet_id: AccountId) -> Result<Self, AssetError> {
        let account_type = faucet_id.account_type();
        if !matches!(account_type, AccountType::FungibleFaucet) {
            return Err(AssetError::FungibleFaucetIdTypeMismatch(faucet_id));
        }

        Ok(Self { faucet_id, amount: Self::DEFAULT_AMOUNT })
    }

    pub fn amount(&mut self, amount: u64) -> Result<&mut Self, AssetError> {
        if amount > FungibleAsset::MAX_AMOUNT {
            return Err(AssetError::FungibleAssetAmountTooBig(amount));
        }

        self.amount = amount;
        Ok(self)
    }

    pub fn with_amount(&self, amount: u64) -> Result<FungibleAsset, AssetError> {
        FungibleAsset::new(self.faucet_id, amount)
    }

    pub fn build(&self) -> Result<FungibleAsset, AssetError> {
        FungibleAsset::new(self.faucet_id, self.amount)
    }
}

impl NonFungibleAsset {
    /// Returns a mocked non-fungible asset, issued by [ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET].
    pub fn mock(asset_data: &[u8]) -> Asset {
        let non_fungible_asset_details = NonFungibleAssetDetails::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET).unwrap().prefix(),
            asset_data.to_vec(),
        )
        .unwrap();
        let non_fungible_asset = NonFungibleAsset::new(&non_fungible_asset_details).unwrap();
        Asset::NonFungible(non_fungible_asset)
    }

    /// Returns the account ID of the issuer of [`NonFungibleAsset::mock()`]
    /// ([ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET]).
    pub fn mock_issuer() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET).unwrap()
    }
}

impl FungibleAsset {
    /// Returns a mocked fungible asset, issued by [ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET].
    pub fn mock(amount: u64) -> Asset {
        Asset::Fungible(
            FungibleAsset::new(
                AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).expect("id should be valid"),
                amount,
            )
            .expect("asset is valid"),
        )
    }

    /// Returns a mocked asset account ID ([ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET]).
    pub fn mock_issuer() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap()
    }
}
