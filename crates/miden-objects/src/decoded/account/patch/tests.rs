use alloc::string::{String, ToString};
use alloc::vec;
use core::num::TryFromIntError;

use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::account::StorageArrayError;

use crate::decoded::account::StorageArrayPatchError;
use crate::decoded::account::test_utils::account_patch;
use crate::proto::account::{StorageArrayPatchEntries, StorageArrayPatchEntry};
use crate::test_utils::error_source;
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn vault_patch_entry_defers_asset_id_validation() {
    let decoded = proto::account::AccountVaultPatchEntry {
        asset_id: Some(Word::empty().into()),
        value: Some(Word::empty().into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.asset_id, Word::empty());
    assert!(decoded.verify().is_err());
}

#[test]
fn vault_patch_verifies_duplicate_ids_and_asset_values() {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    let id = miden_protocol::asset::AssetId::new_fungible(AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    ));
    let entry = proto::account::AccountVaultPatchEntry {
        asset_id: Some(id.to_word().into()),
        value: Some(Word::from([2_u32, 0, 0, 0]).into()),
    };
    assert!(
        proto::account::AccountVaultPatch { entries: vec![entry.clone()] }
            .decode_fields()
            .unwrap()
            .verify()
            .is_ok()
    );
    let decoded = proto::account::AccountVaultPatch {
        entries: vec![entry.clone(), entry.clone()],
    }
    .decode_fields()
    .unwrap();
    assert!(matches!(
        error_source::<crate::decoded::account::VaultPatchError>(&decoded.verify().unwrap_err()),
        Some(crate::decoded::account::VaultPatchError::DuplicateAssetId(actual)) if *actual == id
    ));
    let invalid = proto::account::AccountVaultPatchEntry {
        value: Some(Word::from([1_u32, 2, 0, 0]).into()),
        ..entry
    };
    assert!(
        proto::account::AccountVaultPatch { entries: vec![invalid] }
            .decode_fields()
            .unwrap()
            .verify()
            .is_err()
    );
}

#[test]
fn private_account_update_verifies_empty_payload() {
    let decoded = proto::account::PrivateAccountUpdate {}.decode_fields().unwrap();
    assert_eq!(
        decoded.verify().unwrap(),
        miden_protocol::account::AccountUpdateDetails::Private
    );
}

#[test]
fn storage_map_patch_rejects_empty_updates_after_decoding() {
    let wire = proto::account::StorageMapPatch {
        operation: Some(proto::account::storage_map_patch::Operation::Update(
            proto::account::StorageMapPatchEntries { entries: vec![] },
        )),
    };
    assert!(matches!(
        wire.decode_fields().unwrap().verify(),
        Err(crate::decoded::account::StorageMapPatchError::EmptyUpdate)
    ));
}

#[test]
fn storage_map_patch_rejects_duplicate_keys_after_decoding() {
    use proto::account::storage_map_patch::Operation;

    let entry = proto::account::StorageMapEntry {
        key: Some(Word::empty().into()),
        value: Some(Word::empty().into()),
    };
    let entries = proto::account::StorageMapPatchEntries { entries: vec![entry.clone(), entry] };
    for operation in [Operation::Create(entries.clone()), Operation::Update(entries)] {
        let decoded = proto::account::StorageMapPatch { operation: Some(operation) }
            .decode_fields()
            .unwrap();
        assert!(matches!(
            decoded.verify(),
            Err(crate::decoded::account::StorageMapPatchError::DuplicateKey(_))
        ));
    }
}

#[test]
fn decoded_storage_value_patch_is_a_typed_oneof() {
    use crate::proto::account::StorageValuePatch;
    use crate::proto::account::storage_value_patch::Operation;
    let decoded = StorageValuePatch { operation: Some(Operation::Remove(())) }
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.verify().unwrap(), miden_protocol::account::StorageValuePatch::Remove);
}

#[test]
fn storage_slot_patch_defers_slot_name_validation() {
    let wire = proto::account::StorageSlotPatch {
        slot_name: String::new(),
        patch: Some(proto::account::storage_slot_patch::Patch::Value(
            proto::account::StorageValuePatch {
                operation: Some(proto::account::storage_value_patch::Operation::Remove(())),
            },
        )),
    };
    assert!(wire.decode_fields().unwrap().verify().is_err());
}

#[test]
fn account_patch_protobuf_rejects_unspecified_version_after_decoding() {
    let error = proto::account::AccountPatch {
        version: proto::account::AccountPatchVersion::Unspecified as i32,
        ..proto::account::AccountPatch::from(account_patch())
    }
    .decode_fields()
    .unwrap()
    .verify()
    .map_err(ConversionError::new)
    .unwrap_err();

    assert_eq!(error.to_string(), "account patch version is unspecified");
}

#[test]
fn storage_array_patch_rejects_invalid_entries() -> anyhow::Result<()> {
    for (length, indices, expected) in [
        (3, vec![3], StorageArrayError::IndexOutOfBounds { index: 3, length: 3 }),
        (3, vec![0, 0], StorageArrayError::DuplicateIndex(0)),
        (0, vec![0], StorageArrayError::InvalidLength(0)),
        (257, vec![0], StorageArrayError::InvalidLength(257)),
    ] {
        let wire = StorageArrayPatchEntries {
            length,
            entries: indices
                .into_iter()
                .map(|index| StorageArrayPatchEntry { index, value: Some(Word::empty().into()) })
                .collect(),
        };
        let error = wire.decode_fields()?.verify().unwrap_err();
        let source = error_source::<StorageArrayError>(&error).expect("array validation error");
        assert_eq!(source.to_string(), expected.to_string());
    }
    Ok(())
}

#[test]
fn storage_array_patch_rejects_truncated_indices() -> anyhow::Result<()> {
    // Narrowing this index to u16 would silently turn it into the valid index 0.
    let wire = StorageArrayPatchEntries {
        length: 3,
        entries: vec![StorageArrayPatchEntry {
            index: 1 << 16,
            value: Some(Word::empty().into()),
        }],
    };
    let error = wire.decode_fields()?.verify().unwrap_err();
    assert_matches!(error_source::<TryFromIntError>(&error), Some(_));
    Ok(())
}

#[test]
fn storage_array_patch_rejects_empty_updates_after_decoding() -> anyhow::Result<()> {
    let wire = proto::account::StorageArrayPatch {
        operation: Some(proto::account::storage_array_patch::Operation::Update(
            StorageArrayPatchEntries { length: 3, entries: vec![] },
        )),
    };
    let error = wire.decode_fields()?.verify().unwrap_err();
    assert_matches!(
        error_source::<StorageArrayPatchError>(&error),
        Some(StorageArrayPatchError::EmptyUpdate)
    );
    Ok(())
}
