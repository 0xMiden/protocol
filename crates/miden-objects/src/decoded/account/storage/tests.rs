use alloc::string::ToString;
use alloc::vec;

use assert_matches::assert_matches;
use miden_protocol::Word;

use crate::{DecodeMessage, Verify, proto};

#[test]
fn storage_slot_id_verifies() {
    let decoded = proto::account::StorageSlotId {
        suffix: Some(miden_protocol::Felt::ONE.into()),
        prefix: Some(miden_protocol::Felt::ZERO.into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap().suffix(), miden_protocol::Felt::ONE);
}

#[test]
fn storage_map_entry_verifies() {
    let decoded = proto::account::StorageMapEntry {
        key: Some(Word::empty().into()),
        value: Some(Word::empty().into()),
    }
    .decode_fields()
    .unwrap();
    assert_eq!(decoded.verify().unwrap().1, Word::empty());
}

#[test]
fn account_storage_header_slot_defers_name_validation() {
    let wire = proto::account::account_storage_header::StorageSlot {
        slot_name: "".into(),
        content: Some(proto::account::account_storage_header::storage_slot::Content::MapRoot(
            Word::empty().into(),
        )),
    };
    let decoded = wire.decode_fields().unwrap();
    assert!(matches!(
        decoded.verify(),
        Err(miden_protocol::errors::StorageSlotNameError::TooShort)
    ));
}

#[test]
fn storage_header_defers_duplicate_validation() {
    let slot = proto::account::account_storage_header::StorageSlot {
        slot_name: miden_protocol::account::StorageSlotName::mock(1).as_str().into(),
        content: Some(proto::account::account_storage_header::storage_slot::Content::Value(
            Word::empty().into(),
        )),
    };
    let decoded = proto::account::AccountStorageHeader { slots: vec![slot.clone(), slot] }
        .decode_fields()
        .unwrap();
    assert!(decoded.verify().is_err());
}

#[test]
fn storage_header_verification_reports_the_invalid_slot_index() {
    let slot = proto::account::account_storage_header::StorageSlot {
        slot_name: miden_protocol::account::StorageSlotName::mock(1).as_str().into(),
        content: Some(proto::account::account_storage_header::storage_slot::Content::Value(
            Word::empty().into(),
        )),
    };
    let invalid = proto::account::account_storage_header::StorageSlot {
        slot_name: "".into(),
        ..slot.clone()
    };
    let error = proto::account::AccountStorageHeader { slots: vec![slot, invalid] }
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap_err();

    assert!(error.to_string().starts_with("slots[1]:"), "{error}");
    assert!(matches!(
        crate::test_utils::error_source::<miden_protocol::errors::StorageSlotNameError>(&error),
        Some(miden_protocol::errors::StorageSlotNameError::TooShort)
    ));
}

/// Returns a wire storage slot with the mock name at `index` and an empty value.
fn value_slot(index: usize) -> proto::account::StorageSlot {
    proto::account::StorageSlot {
        slot_name: miden_protocol::account::StorageSlotName::mock(index).as_str().into(),
        storage_slot_content: Some(proto::account::storage_slot::StorageSlotContent::Value(
            Word::empty().into(),
        )),
    }
}

#[test]
fn account_storage_rejects_duplicate_slot_names() {
    let slot = value_slot(1);
    let error = proto::account::AccountStorage { slots: vec![slot.clone(), slot] }
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap_err();

    assert_matches!(
        crate::test_utils::error_source::<miden_protocol::errors::AccountError>(&error),
        Some(miden_protocol::errors::AccountError::DuplicateStorageSlotName(_))
    );
}

#[test]
fn account_storage_rejects_more_slots_than_the_maximum() {
    let num_slots = miden_protocol::account::AccountStorage::MAX_NUM_STORAGE_SLOTS + 1;
    let slots = (0..num_slots).map(value_slot).collect();
    let error = proto::account::AccountStorage { slots }
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap_err();

    assert_matches!(
        crate::test_utils::error_source::<miden_protocol::errors::AccountError>(&error),
        Some(miden_protocol::errors::AccountError::StorageTooManySlots(count))
            if *count == num_slots as u64
    );
}

#[test]
fn storage_map_rejects_an_empty_value() {
    let key = miden_protocol::account::StorageMapKey::from_raw(Word::from([1_u32, 2, 3, 4]));
    let entry = proto::account::StorageMapEntry {
        key: Some(Word::from(key).into()),
        value: Some(Word::empty().into()),
    };
    let error = proto::account::StorageMap { entries: vec![entry] }
        .decode_fields()
        .unwrap()
        .verify()
        .unwrap_err();

    assert_matches!(
        crate::test_utils::error_source::<crate::decoded::account::StorageMapEntryError>(&error),
        Some(crate::decoded::account::StorageMapEntryError::EmptyValue(empty)) if *empty == key
    );
}
