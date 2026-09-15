use crate::test_utils::error_source;
use crate::{DecodeMessage, Verify, proto};

mod common;

mod errors;

mod roundtrip;

#[test]
fn foreign_account_slot_name_defers_name_and_id_validation() {
    let name = miden_protocol::account::StorageSlotName::mock(1);
    let wire = proto::transaction::ForeignAccountSlotName {
        slot_id: Some(name.id().into()),
        slot_name: name.as_str().into(),
    };
    assert_eq!(wire.clone().decode_fields().unwrap().verify().unwrap(), (name.id(), name));
    let invalid =
        proto::transaction::ForeignAccountSlotName { slot_name: "".into(), ..wire.clone() };
    assert!(invalid.decode_fields().unwrap().verify().is_err());
    let mismatched = proto::transaction::ForeignAccountSlotName {
        slot_name: miden_protocol::account::StorageSlotName::mock(2).as_str().into(),
        ..wire
    };
    assert!(matches!(
        error_source::<crate::decoded::transaction::ForeignAccountSlotNameError>(
            &mismatched.decode_fields().unwrap().verify().unwrap_err()
        ),
        Some(crate::decoded::transaction::ForeignAccountSlotNameError::IdMismatch { .. })
    ));
}
