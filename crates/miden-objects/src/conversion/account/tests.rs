use alloc::vec;

use miden_protocol::account::{
    AccountCode,
    AccountId,
    AccountStorage,
    AccountStorageHeader,
    PartialAccount,
    PartialStorage,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotHeader,
    StorageSlotId,
    StorageSlotName,
    StorageSlotType,
};
use miden_protocol::asset::PartialVault;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::{Felt, Word};
use prost::Message;

use crate::decoded::account::test_utils::{
    account_header,
    dummy_account_id,
    partial_account,
    private_account_id,
};
use crate::{DecodeMessage, Verify, proto};

#[test]
fn account_id_oneof_roundtrip() {
    use miden_protocol::account::{AccountId, AccountIdV1, AccountType, AssetCallbackFlag};
    use prost::Message;

    let id = AccountId::V1(AccountIdV1::dummy(
        [7; 15],
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    ));
    let bytes = proto::account::AccountId::from(id).encode_to_vec();
    let wire = proto::account::AccountId::decode(bytes.as_slice()).unwrap();
    let decoded = wire.decode_fields().unwrap();
    let proto::account::account_id::DecodedVersion::V1(v1) = &decoded.version;
    assert_eq!(v1.suffix, id.suffix());
    assert_eq!(v1.prefix, id.prefix().as_felt());
    assert_eq!(decoded.verify().unwrap(), id);
    assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), id);
}

#[test]
fn account_id_v1_roundtrip() {
    use miden_protocol::account::{AccountIdV1, AccountType, AssetCallbackFlag};

    for account_type in [AccountType::Private, AccountType::Public] {
        for callbacks in [AssetCallbackFlag::Disabled, AssetCallbackFlag::Enabled] {
            let id = AccountIdV1::dummy([7; 15], account_type, callbacks);
            let decoded = proto::account::AccountIdV1::from(id).decode_fields().unwrap();
            assert_eq!(decoded.suffix, id.suffix());
            assert_eq!(decoded.prefix, id.prefix().as_felt());
            assert_eq!(decoded.verify().unwrap(), id);
            assert_eq!(
                proto::account::AccountIdV1::from(&id)
                    .decode_fields()
                    .unwrap()
                    .verify()
                    .unwrap(),
                id
            );
        }
    }
}

fn account_witness(account_id: AccountId) -> AccountWitness {
    let path = SparseMerklePath::from_parts(u64::MAX, vec![]).unwrap();
    AccountWitness::new(account_id, Word::empty(), path).unwrap()
}

#[test]
fn account_witness_protobuf_round_trip() {
    let witness = account_witness(private_account_id());

    let message: proto::account::AccountWitness = (&witness).into();
    let decoded = message.decode_fields().unwrap().verify().unwrap();

    assert_eq!(decoded, witness);
}

#[test]
fn account_header_roundtrips_through_explicit_versioned_protobuf_bytes() {
    let header = account_header();

    let encoded = proto::account::AccountHeader::from(&header).encode_to_vec();
    let message = proto::account::AccountHeader::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.version, proto::account::AccountVersion::V1 as i32);
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), header);
}

#[test]
fn account_storage_header_roundtrips_value_and_map_root_payloads() {
    use proto::account::account_storage_header::storage_slot::Content;

    for slot_type in [StorageSlotType::Value, StorageSlotType::Map] {
        for value in [Word::empty(), Word::from([1_u32, 2, 3, 4])] {
            let header = AccountStorageHeader::new(vec![StorageSlotHeader::new(
                StorageSlotName::new("miden::test::storage").unwrap(),
                slot_type,
                value,
            )])
            .unwrap();

            let message = proto::account::AccountStorageHeader::from(&header);
            match (slot_type, message.slots[0].content.as_ref().unwrap()) {
                (StorageSlotType::Value, Content::Value(encoded))
                | (StorageSlotType::Map, Content::MapRoot(encoded)) => {
                    assert_eq!(encoded, &proto::primitives::Word::from(value));
                },
                _ => panic!("storage slot kind changed"),
            }
            let message =
                proto::account::AccountStorageHeader::decode(message.encode_to_vec().as_slice())
                    .unwrap();
            assert_eq!(message.decode_fields().unwrap().verify().unwrap(), header);
        }
    }
}

#[test]
fn storage_slot_id_roundtrips_through_protobuf_bytes() {
    let id = StorageSlotId::new(Felt::from(1_u32), Felt::from(2_u32));

    let encoded = proto::account::StorageSlotId::from(id).encode_to_vec();
    let message = proto::account::StorageSlotId::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), id);
}

#[test]
fn partial_account_roundtrips_through_protobuf_bytes() {
    let account = partial_account();

    let encoded = proto::account::PartialAccount::from(&account).encode_to_vec();
    let message = proto::account::PartialAccount::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), account);
}

#[test]
fn partial_account_encoding_canonicalizes_map_like_fields() {
    let key_a = StorageMapKey::from_index(1);
    let key_b = StorageMapKey::from_index(2);
    let storage_map = StorageMap::with_entries([
        (key_a, Word::from([11_u32, 0, 0, 0])),
        (key_b, Word::from([12_u32, 0, 0, 0])),
    ])
    .unwrap();
    let storage =
        AccountStorage::new(vec![StorageSlot::with_map(StorageSlotName::mock(1), storage_map)])
            .unwrap();
    let partial_storage = PartialStorage::new_full(storage);
    let account = PartialAccount::new(
        dummy_account_id(7),
        Felt::ONE,
        AccountCode::mock(),
        partial_storage,
        PartialVault::new(Word::empty()),
        None,
    )
    .unwrap();

    let message = proto::account::PartialAccount::from(account);
    let keys = &message.storage.unwrap().maps[0].keys;

    assert_eq!(keys, &vec![Word::from(key_a).into(), Word::from(key_b).into()]);
}
