use crate::account::AccountId;
use crate::asset::{Asset, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails};
use crate::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET,
};

impl NonFungibleAsset {
    /// Returns a mocked non-fungible asset, issued by [ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET].
    pub fn mock(asset_data: &[u8]) -> Asset {
        let non_fungible_asset_details = NonFungibleAssetDetails::new(
            AccountId::try_from(ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET).unwrap(),
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
