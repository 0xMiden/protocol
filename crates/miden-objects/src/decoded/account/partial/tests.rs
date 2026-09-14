use alloc::vec;

use assert_matches::assert_matches;
use miden_protocol::account::{
    AccountStorage,
    PartialStorage,
    PartialStorageMap,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{
    Asset,
    AssetId,
    AssetVault,
    FungibleAsset,
    NonFungibleAsset,
    PartialVault,
};
use miden_protocol::crypto::merkle::smt::{PartialSmt, Smt};
use miden_protocol::errors::{AccountError, AssetError, PartialAssetVaultError};
use miden_protocol::{Felt, Word};

use crate::decoded::account::test_utils::{dummy_account_id, partial_account};
use crate::test_utils::error_source;
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn partial_account_preserves_seed_validation_source() {
    let mut message = proto::account::PartialAccount::from(partial_account());
    message.seed = Some(Word::empty().into());

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<AccountError>(&error),
        Some(AccountError::ExistingAccountWithSeed)
    );
}

#[test]
fn partial_account_rejects_new_account_without_seed() {
    let mut message = proto::account::PartialAccount::from(partial_account());
    message.nonce = Some(Felt::ZERO.into());

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<AccountError>(&error),
        Some(AccountError::NewAccountMissingSeed)
    );
}

#[test]
fn partial_storage_rejects_duplicate_roots_before_collection() {
    let mut message = proto::account::PartialStorage::from(partial_account().storage());
    let map = proto::account::PartialStorageMap {
        smt: Some(PartialSmt::new(Word::from([9_u32, 0, 0, 0])).into()),
        keys: vec![],
    };
    message.maps = vec![map.clone(), map];

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<crate::decoded::account::PartialStorageError>(&error),
        Some(crate::decoded::account::PartialStorageError::DuplicateRoot(root))
            if *root == Word::from([9_u32, 0, 0, 0])
    );
}

#[test]
fn partial_storage_preserves_root_not_in_header_source() {
    let mut message = proto::account::PartialStorage::from(partial_account().storage());
    message.maps.push(proto::account::PartialStorageMap {
        smt: Some(PartialSmt::new(Word::from([9_u32, 0, 0, 0])).into()),
        keys: vec![],
    });

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<AccountError>(&error),
        Some(AccountError::StorageMapRootNotFound(root)) if *root == Word::from([9_u32, 0, 0, 0])
    );
}

#[test]
fn partial_storage_map_rejects_duplicate_raw_keys() {
    let key = StorageMapKey::from_index(1);
    let storage_map = StorageMap::with_entries([(key, Word::from([2_u32, 0, 0, 0]))]).unwrap();
    let mut message: proto::account::PartialStorageMap =
        PartialStorageMap::new_full(storage_map).into();
    message.keys.push(Word::from(key).into());

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<miden_protocol::crypto::merkle::MerkleError>(&error),
        Some(miden_protocol::crypto::merkle::MerkleError::DuplicateValuesForIndex(_))
    );
}

#[test]
fn partial_storage_map_rejects_untracked_raw_keys() {
    let mut message: proto::account::PartialStorageMap =
        PartialStorageMap::new(Word::empty()).into();
    message.keys = vec![Word::from(StorageMapKey::from_index(1)).into()];

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<miden_protocol::crypto::merkle::MerkleError>(&error),
        Some(miden_protocol::crypto::merkle::MerkleError::UntrackedKey(_))
    );
}

#[test]
fn partial_vault_rejects_duplicate_asset_ids() {
    let id = AssetId::new_fungible(dummy_account_id(9));
    let asset = Asset::new(id, Word::from([2_u32, 0, 0, 0])).unwrap();
    let mut message: proto::account::PartialVault =
        PartialVault::new_full(AssetVault::new(&[asset]).unwrap()).into();
    message.asset_ids.push(Word::from(id).into());

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<PartialAssetVaultError>(&error),
        Some(PartialAssetVaultError::DuplicateAssetId(actual)) if *actual == id
    );
}

#[test]
fn partial_vault_preserves_invalid_asset_id_source() {
    let mut message: proto::account::PartialVault = PartialVault::new(Word::empty()).into();
    message.asset_ids = vec![Word::empty().into()];

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(error_source::<AssetError>(&error), Some(AssetError::UnknownAssetIdVersion(0)));
}

#[test]
fn partial_vault_preserves_invalid_asset_value_source() {
    let id = AssetId::new_fungible(dummy_account_id(9));
    let smt = Smt::with_entries([(id.hash().as_word(), Word::from([1_u32, 2, 0, 0]))]).unwrap();
    let message = proto::account::PartialVault {
        smt: Some(PartialSmt::from_proofs([smt.open(&id.hash().as_word())]).unwrap().into()),
        asset_ids: vec![Word::from(id).into()],
    };

    let error = message
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<PartialAssetVaultError>(&error),
        Some(PartialAssetVaultError::InvalidAssetForId {
            source: AssetError::FungibleAssetValueMostSignificantElementsMustBeZero(_),
            ..
        })
    );
}

#[test]
fn partial_storage_decoding_normalizes_map_order() {
    let storage = AccountStorage::new(vec![
        StorageSlot::with_empty_map(StorageSlotName::mock(1)),
        StorageSlot::with_empty_map(StorageSlotName::mock(2)),
    ])
    .unwrap();
    let partial_storage = PartialStorage::new_full(storage);
    let expected = proto::account::PartialStorage::from(&partial_storage);
    let mut unordered = expected.clone();
    unordered.maps.reverse();

    let decoded = unordered.decode_fields().unwrap().verify().unwrap();

    assert_eq!(proto::account::PartialStorage::from(decoded), expected);
}

#[test]
fn partial_vault_decoding_normalizes_asset_id_order() {
    let vault =
        AssetVault::new(&[FungibleAsset::mock(2), NonFungibleAsset::mock(&[1, 2, 3])]).unwrap();
    let expected: proto::account::PartialVault = PartialVault::new_full(vault).into();
    let mut unordered = expected.clone();
    unordered.asset_ids.reverse();

    let decoded = unordered.decode_fields().unwrap().verify().unwrap();

    assert_eq!(proto::account::PartialVault::from(decoded), expected);
}
