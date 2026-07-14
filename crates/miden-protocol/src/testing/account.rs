use super::constants::{FUNGIBLE_ASSET_AMOUNT, NON_FUNGIBLE_ASSET_DATA};
use crate::Felt;
use crate::account::{Account, AccountCode, AccountId, AccountStorage};
use crate::asset::{Asset, AssetVault, FungibleAsset, NonFungibleAsset};
use crate::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};

impl Account {
    /// Returns an [`Account`] instantiated with the provided components.
    ///
    /// This is a thin wrapper around [`Account::new`] that assumes the provided components are for
    /// an existing account. See that method's docs for details on when this function panics.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the provided components are not for an existing account.
    pub fn new_existing(
        id: AccountId,
        vault: AssetVault,
        storage: AccountStorage,
        code: AccountCode,
        nonce: Felt,
    ) -> Self {
        Self::new(id, vault, storage, code, nonce, None)
            .expect("account seed is invalid for provided account")
    }
}

impl AssetVault {
    /// Creates an [AssetVault] with 4 default assets.
    ///
    /// The ids of the assets added to the vault are defined by the following constants:
    ///
    /// - ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET
    /// - ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1
    /// - ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2
    /// - ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET
    pub fn mock() -> Self {
        let faucet_id: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
        let fungible_asset =
            Asset::Fungible(FungibleAsset::new(faucet_id, FUNGIBLE_ASSET_AMOUNT).unwrap());

        let faucet_id_1: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap();
        let fungible_asset_1 =
            Asset::Fungible(FungibleAsset::new(faucet_id_1, FUNGIBLE_ASSET_AMOUNT).unwrap());

        let faucet_id_2: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap();
        let fungible_asset_2 =
            Asset::Fungible(FungibleAsset::new(faucet_id_2, FUNGIBLE_ASSET_AMOUNT).unwrap());

        let non_fungible_asset = NonFungibleAsset::mock(&NON_FUNGIBLE_ASSET_DATA);
        AssetVault::new(&[fungible_asset, fungible_asset_1, fungible_asset_2, non_fungible_asset])
            .unwrap()
    }
}
