use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountType,
};
use miden_protocol::asset::AssetVault;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;

use crate::testing::account_component::{MockAccountComponent, MockFaucetComponent};

// MOCK ACCOUNT EXT
// ================================================================================================

/// Extension trait for [`Account`]s that return mocked accounts.
pub trait MockAccountExt {
    /// Creates an existing mock account with the provided auth component.
    fn mock(account_id: u128, auth: impl Into<AccountComponent>) -> Account {
        let account_id = AccountId::try_from(account_id).unwrap();
        let account = AccountBuilder::new([1; 32])
            .account_type(account_id.account_type())
            .with_auth_component(auth)
            .with_component(MockAccountComponent::with_slots(AccountStorage::mock_storage_slots()))
            .with_assets(AssetVault::mock().assets())
            .build_existing()
            .expect("account should be valid");
        let (_id, vault, storage, code, nonce, _seed) = account.into_parts();

        Account::new_existing(account_id, vault, storage, code, nonce)
    }

    /// Creates a mock account with fungible faucet storage and the given account ID.
    fn mock_fungible_faucet(account_id: u128) -> Account {
        let account_id = AccountId::try_from(account_id).unwrap();
        assert_eq!(account_id.account_type(), AccountType::FungibleFaucet);

        let account = AccountBuilder::new([1; 32])
            .account_type(account_id.account_type())
            .with_auth_component(NoopAuthComponent)
            .with_component(MockFaucetComponent)
            .build_existing()
            .expect("account should be valid");
        let (_id, vault, storage, code, nonce, _seed) = account.into_parts();

        Account::new_existing(account_id, vault, storage, code, nonce)
    }

    /// Creates a mock account with non-fungible faucet storage and the given account ID.
    fn mock_non_fungible_faucet(account_id: u128) -> Account {
        let account_id = AccountId::try_from(account_id).unwrap();
        assert_eq!(account_id.account_type(), AccountType::NonFungibleFaucet);

        let account = AccountBuilder::new([1; 32])
            .account_type(account_id.account_type())
            .with_auth_component(NoopAuthComponent)
            .with_component(MockFaucetComponent)
            .build_existing()
            .expect("account should be valid");
        let (_id, vault, storage, code, nonce, _seed) = account.into_parts();

        Account::new_existing(account_id, vault, storage, code, nonce)
    }
}

impl MockAccountExt for Account {}
