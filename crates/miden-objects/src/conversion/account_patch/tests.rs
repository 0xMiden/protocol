use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountStoragePatch,
    StorageMapPatch,
    StorageSlotName,
    StorageSlotPatch,
    StorageValuePatch,
};
use prost::Message;

use crate::decoded::account::test_utils::account_patch;
use crate::{DecodeMessage, Verify, proto};

#[test]
fn storage_map_patch_oneof_roundtrips_all_operations() {
    use miden_protocol::account::{StorageMapKey, StorageMapPatch, StorageMapPatchEntries};
    use prost::Message;

    let entries: StorageMapPatchEntries = [
        (StorageMapKey::from_raw(Word::from([1_u32, 0, 0, 0])), Word::empty()),
        (
            StorageMapKey::from_raw(Word::from([2_u32, 0, 0, 0])),
            Word::from([3_u32, 0, 0, 0]),
        ),
    ]
    .into_iter()
    .collect();
    for patch in [
        StorageMapPatch::Create { entries: StorageMapPatchEntries::new() },
        StorageMapPatch::Create { entries: entries.clone() },
        StorageMapPatch::Update { entries },
        StorageMapPatch::Remove,
    ] {
        let bytes = proto::account::StorageMapPatch::from(&patch).encode_to_vec();
        let wire = proto::account::StorageMapPatch::decode(bytes.as_slice()).unwrap();
        assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), patch);
    }
}

#[test]
fn account_patch_roundtrips_through_explicit_versioned_protobuf_bytes() {
    let patch = account_patch();

    let encoded = proto::account::AccountPatch::from(&patch).encode_to_vec();
    let message = proto::account::AccountPatch::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.version, proto::account::AccountPatchVersion::V1 as i32);
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), patch);
}

#[test]
fn account_storage_patch_protobuf_slots_follow_canonical_storage_order() {
    let storage_patch = AccountStoragePatch::from_entries([
        (StorageSlotName::mock(3), StorageSlotPatch::Value(StorageValuePatch::Remove)),
        (StorageSlotName::mock(1), StorageSlotPatch::Map(StorageMapPatch::Remove)),
        (StorageSlotName::mock(4), StorageSlotPatch::Value(StorageValuePatch::Remove)),
        (StorageSlotName::mock(2), StorageSlotPatch::Map(StorageMapPatch::Remove)),
    ])
    .unwrap();

    let expected_slots = [
        ("miden::test::slot::3", true),
        ("miden::test::slot::1", false),
        ("miden::test::slot::4", true),
        ("miden::test::slot::2", false),
    ];
    let message = proto::account::AccountStoragePatch::from(&storage_patch);

    assert_eq!(
        message
            .slots
            .iter()
            .map(|slot| {
                (
                    slot.slot_name.as_str(),
                    matches!(
                        slot.patch.as_ref(),
                        Some(proto::account::storage_slot_patch::Patch::Value(_))
                    ),
                )
            })
            .collect::<Vec<_>>(),
        expected_slots
    );
}

#[test]
fn storage_value_patch_oneof_roundtrips_all_operations() {
    use proto::account::storage_value_patch::Operation;

    for value in [Word::empty(), Word::from([1_u32, 2, 3, 4])] {
        for (patch, expected) in [
            (StorageValuePatch::Create { value }, Operation::Create(value.into())),
            (StorageValuePatch::Update { value }, Operation::Update(value.into())),
            (StorageValuePatch::Remove, Operation::Remove(())),
        ] {
            let message = proto::account::StorageValuePatch::from(&patch);
            assert_eq!(message.operation, Some(expected));
            let encoded = message.encode_to_vec();
            let decoded = proto::account::StorageValuePatch::decode(encoded.as_slice()).unwrap();
            assert_eq!(decoded.decode_fields().unwrap().verify().unwrap(), patch);
        }
    }
}

#[test]
fn storage_value_patch_nested_in_account_storage_patch_roundtrips() {
    let patch = AccountStoragePatch::from_entries([
        (
            StorageSlotName::mock(1),
            StorageSlotPatch::Value(StorageValuePatch::Create { value: Word::empty() }),
        ),
        (
            StorageSlotName::mock(2),
            StorageSlotPatch::Value(StorageValuePatch::Update {
                value: Word::from([1_u32, 0, 0, 0]),
            }),
        ),
        (StorageSlotName::mock(3), StorageSlotPatch::Value(StorageValuePatch::Remove)),
    ])
    .unwrap();
    let message = proto::account::AccountStoragePatch::from(&patch);
    let encoded = message.encode_to_vec();
    let decoded = proto::account::AccountStoragePatch::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded.decode_fields().unwrap().verify().unwrap(), patch);
}
