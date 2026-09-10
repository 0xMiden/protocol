use alloc::vec;

use miden_protocol::account::{
    AccountCode,
    AccountHeader,
    AccountId,
    AccountIdVersion,
    AccountPatch,
    AccountStorageHeader,
    AccountStoragePatch,
    AccountType,
    AccountVaultPatch,
    AssetCallbackFlag,
    PartialAccount,
    PartialStorage,
};
use miden_protocol::asset::PartialVault;
use miden_protocol::{Felt, Word};

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
