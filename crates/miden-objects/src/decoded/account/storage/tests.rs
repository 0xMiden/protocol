use alloc::vec;

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
fn storage_slot_defers_name_validation() {
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
