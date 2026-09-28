use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountHeader,
    AccountId,
    AccountIdVersion,
    AccountPatch,
    AccountStorage,
    AccountStorageHeader,
    AccountStoragePatch,
    AccountType,
    AccountVaultPatch,
    AssetCallbackFlag,
    PartialAccount,
    PartialStorage,
};
use miden_protocol::asset::{AssetVault, PartialVault};
use miden_protocol::testing::add_component::AddComponent;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::{Felt, Word};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub(crate) fn private_account_id() -> AccountId {
    AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

pub(crate) fn account_header() -> AccountHeader {
    AccountHeader::new(
        private_account_id(),
        Felt::ONE,
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        Word::from([9_u32, 10, 11, 12]),
    )
}

pub(crate) fn account_patch() -> AccountPatch {
    AccountPatch::new(
        private_account_id(),
        AccountStoragePatch::from_entries([]).unwrap(),
        AccountVaultPatch::new([].into()).unwrap(),
        None,
        None,
    )
    .unwrap()
}

pub(crate) fn dummy_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

pub(crate) fn partial_account() -> PartialAccount {
    PartialAccount::new(
        dummy_account_id(7),
        Felt::ONE,
        AccountCode::mock(),
        PartialStorage::new(AccountStorageHeader::new(vec![]).unwrap(), []).unwrap(),
        PartialVault::new(Word::empty()),
        None,
    )
    .unwrap()
}

pub(crate) fn mock_account() -> Account {
    Account::new_existing(
        dummy_account_id(7),
        AssetVault::mock(),
        AccountStorage::mock(),
        AccountCode::mock(),
        Felt::ONE,
    )
}

/// Returns an account that is not yet created on chain, so it carries its seed.
pub(crate) fn mock_new_account() -> Account {
    Account::builder([5; 32])
        .with_component(NoopAuthComponent)
        .with_component(AddComponent)
        .build()
        .unwrap()
}

/// Returns one deterministic secret key per [`AuthScheme`].
pub(crate) fn auth_secret_keys() -> Vec<AuthSecretKey> {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    [AuthScheme::Falcon512Poseidon2, AuthScheme::EcdsaK256Keccak]
        .into_iter()
        .map(|scheme| {
            AuthSecretKey::with_scheme_and_rng(scheme, &mut rng)
                .expect("every scheme has a secret key")
        })
        .collect()
}
