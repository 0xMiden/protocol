use assert_matches::assert_matches;
use miden_protocol::account::delta::AssetDeltaOperation;
use miden_protocol::account::{
    AccountCode,
    AccountCodePatch,
    AccountDelta,
    AccountStoragePatch,
    AccountVaultDelta,
    AssetDelta,
    StorageSlotName,
    StorageSlotPatch,
    StorageValuePatch,
};
use miden_protocol::asset::{FungibleAsset, NonFungibleAsset};
use miden_protocol::{Felt, Word};
use prost::Message;

use crate::decoded::account::AccountDeltaError;
use crate::decoded::account::test_utils::private_account_id;
use crate::test_utils::error_source;
use crate::{DecodeMessage, Verify, proto};

fn empty_delta() -> AccountDelta {
    AccountDelta::new(
        private_account_id(),
        AccountStoragePatch::default(),
        AccountVaultDelta::default(),
        AccountCodePatch::default(),
        Felt::ZERO,
    )
    .unwrap()
}

fn full_delta() -> AccountDelta {
    let storage = AccountStoragePatch::from_entries([(
        StorageSlotName::mock(1),
        StorageSlotPatch::Value(StorageValuePatch::Update { value: Word::from([1_u32, 2, 3, 4]) }),
    )])
    .unwrap();
    let vault = AccountVaultDelta::new([
        AssetDelta::new(AssetDeltaOperation::Add, FungibleAsset::mock(42)),
        AssetDelta::new(AssetDeltaOperation::Remove, NonFungibleAsset::mock(&[1, 2, 3])),
    ])
    .unwrap();

    AccountDelta::new(
        private_account_id(),
        storage,
        vault,
        AccountCodePatch::new(Some(AccountCode::mock())),
        Felt::from(3_u32),
    )
    .unwrap()
}

#[rstest::rstest]
#[case::empty(empty_delta())]
#[case::full(full_delta())]
fn account_delta_roundtrips(#[case] delta: AccountDelta) -> anyhow::Result<()> {
    let bytes = proto::account::AccountDelta::from(&delta).encode_to_vec();
    let message = proto::account::AccountDelta::decode(bytes.as_slice())?;
    assert_eq!(message.decode_fields()?.verify()?, delta);

    Ok(())
}

#[test]
fn account_delta_rejects_unspecified_version() -> anyhow::Result<()> {
    let mut message = proto::account::AccountDelta::from(&full_delta());
    message.version = proto::account::AccountDeltaVersion::Unspecified as i32;

    let error = message.decode_fields()?.verify().unwrap_err();
    assert_matches!(
        error_source::<AccountDeltaError>(&error),
        Some(AccountDeltaError::UnspecifiedVersion)
    );

    Ok(())
}
