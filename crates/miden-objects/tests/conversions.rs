use core::error::Error;

use miden_objects::conversion::decode_standalone_proven_batch;
use miden_objects::{ConversionError, proto};
use miden_protocol::account::{
    AccountHeader,
    AccountId,
    AccountIdVersion,
    AccountStorageHeader,
    AccountStoragePatch,
    AccountType,
    AccountUpdateDetails,
    AssetCallbackFlag,
    StorageMapPatch,
    StorageSlotHeader,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
    StorageValuePatch,
};
use miden_protocol::batch::BatchAccountUpdate;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockAccountUpdate, BlockBody, BlockHeader};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::errors::{AccountIdError, BlockBodyError, TransactionHeaderError};
use miden_protocol::note::{Note, NoteId, NoteInclusionProof};
use miden_protocol::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
    ProvenTransaction,
    TransactionHeader,
    TxAccountUpdate,
};
use miden_protocol::vm::ExecutionProof;
use miden_protocol::{Felt, Word};
use prost::Message;

#[test]
fn conversion_error_preserves_deserialization_error_source() {
    use miden_protocol::utils::serde::DeserializationError;

    let error = ConversionError::deserialization(
        "AccountId",
        DeserializationError::InvalidValue("invalid account id".into()),
    );

    assert_eq!(
        error.to_string(),
        "failed to deserialize AccountId: invalid value: invalid account id"
    );
    assert!(matches!(
        error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<DeserializationError>()),
        Some(DeserializationError::InvalidValue(message)) if message == "invalid account id"
    ));
}

fn private_account_id() -> AccountId {
    AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

fn account_witness(account_id: AccountId) -> AccountWitness {
    let path = SparseMerklePath::from_parts(u64::MAX, vec![]).unwrap();
    AccountWitness::new(account_id, Word::empty(), path).unwrap()
}

#[test]
fn account_witness_protobuf_round_trip() {
    let witness = account_witness(private_account_id());

    let message: proto::account::AccountWitness = (&witness).into();
    let decoded = AccountWitness::try_from(message).unwrap();

    assert_eq!(decoded, witness);
}

#[test]
fn account_witness_protobuf_requires_witness_id() {
    let error = AccountWitness::try_from(proto::account::AccountWitness {
        commitment: Some(Word::empty().into()),
        path: Some(proto::primitives::SparseMerklePath {
            empty_nodes_mask: u64::MAX,
            siblings: vec![],
        }),
        ..Default::default()
    })
    .unwrap_err();

    assert!(error.to_string().ends_with("::witness_id is missing"));
}

#[test]
fn account_witness_conversion_preserves_account_tree_error_source() {
    let account_id = private_account_id();
    let error = AccountWitness::try_from(proto::account::AccountWitness {
        witness_id: Some(account_id.into()),
        commitment: Some(Word::empty().into()),
        path: Some(proto::primitives::SparseMerklePath::default()),
        ..Default::default()
    })
    .unwrap_err();

    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<miden_protocol::errors::AccountTreeError>()),
        Some(
            miden_protocol::errors::AccountTreeError::WitnessMerklePathDepthDoesNotMatchAccountTreeDepth(0)
        )
    ));
}

#[test]
fn account_id_protobuf_requires_exactly_15_bytes() {
    for id in [vec![0; AccountId::SERIALIZED_SIZE - 1], vec![0; AccountId::SERIALIZED_SIZE + 1]] {
        let error = AccountId::try_from(proto::account::AccountId { id }).unwrap_err();

        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<core::array::TryFromSliceError>())
                .is_some()
        );
    }
}

#[test]
fn account_id_protobuf_rejects_invalid_metadata() {
    let mut id = <[u8; AccountId::SERIALIZED_SIZE]>::from(private_account_id());
    id[7] &= 0b1111_0000;

    let error = AccountId::try_from(proto::account::AccountId { id: id.into() }).unwrap_err();

    assert!(matches!(
        error.source().and_then(|source| source.downcast_ref::<AccountIdError>()),
        Some(AccountIdError::UnknownAccountIdVersion(0))
    ));
}

#[test]
fn account_header_protobuf_preserves_invalid_nonce_source() {
    let error = AccountHeader::try_from(proto::account::AccountHeader {
        account_id: Some(private_account_id().into()),
        vault_root: Some(Word::empty().into()),
        storage_commitment: Some(Word::empty().into()),
        code_commitment: Some(Word::empty().into()),
        nonce: Felt::ORDER,
    })
    .unwrap_err();

    assert!(error.to_string().starts_with("nonce: "));
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<<Felt as TryFrom<u64>>::Error>()),
        Some(source) if source.as_u64() == Felt::ORDER
    ));
}

fn assert_missing_block_number(error: ConversionError, field: &str) {
    let error = error.to_string();
    assert!(error.starts_with(&format!("{field}: field ")));
    assert!(error.ends_with(&format!("::{field} is missing")));
}

fn proven_transaction_data() -> proto::transaction::ProvenTransactionData {
    let account_update = TxAccountUpdate::new(
        private_account_id(),
        Word::empty(),
        Word::from([1_u32, 0, 0, 0]),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();

    proto::transaction::ProvenTransactionData {
        account_update: Some((&account_update).into()),
        input_notes: vec![],
        output_notes: vec![],
        reference_block_num: Some(proto::blockchain::BlockNumber { block_num: 1 }),
        reference_block_commitment: Some(Word::empty().into()),
        expiration_block_num: Some(proto::blockchain::BlockNumber { block_num: 2 }),
        proof: Some(ExecutionProof::new_dummy().into()),
    }
}

fn proven_batch_data() -> proto::transaction::ProvenBatch {
    proto::transaction::ProvenBatch {
        reference_block_commitment: Some(Word::empty().into()),
        reference_block_num: Some(proto::blockchain::BlockNumber { block_num: 1 }),
        account_updates: vec![],
        input_notes: vec![],
        output_notes: vec![],
        expiration_block_num: Some(proto::blockchain::BlockNumber { block_num: 2 }),
        transactions: vec![],
        proof: Some(ExecutionProof::new_dummy().into()),
    }
}

#[test]
fn account_update_roundtrips_through_protobuf_bytes() {
    let update = BatchAccountUpdate::new(
        private_account_id(),
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        AccountUpdateDetails::Private,
    )
    .unwrap();

    let encoded = proto::transaction::BatchAccountUpdate::from(&update).encode_to_vec();
    let message = proto::transaction::BatchAccountUpdate::decode(encoded.as_slice()).unwrap();
    assert_eq!(BatchAccountUpdate::try_from(message).unwrap(), update);
}

#[test]
fn block_body_and_transaction_header_roundtrip() {
    let account_id = private_account_id();
    let transaction = TransactionHeader::new(
        account_id,
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        InputNotes::default(),
        vec![],
    )
    .unwrap();
    let account_update = BlockAccountUpdate::new(
        account_id,
        transaction.final_state_commitment(),
        AccountUpdateDetails::Private,
    )
    .unwrap();
    let body = BlockBody::new(
        vec![account_update],
        vec![],
        vec![],
        OrderedTransactionHeaders::new_unchecked(vec![transaction]),
    )
    .unwrap();

    let encoded = proto::blockchain::BlockBody::from(&body).encode_to_vec();
    let message = proto::blockchain::BlockBody::decode(encoded.as_slice()).unwrap();
    assert_eq!(BlockBody::try_from(message).unwrap(), body);
}

#[test]
fn account_storage_header_rejects_invalid_slot_types() {
    for (slot_type, expected_message) in [
        (Default::default(), "storage slot type is unspecified"),
        (i32::MAX, "unknown storage slot type 2147483647"),
    ] {
        let message = proto::account::AccountStorageHeader {
            slots: vec![proto::account::account_storage_header::StorageSlot {
                slot_name: "miden::test::storage".into(),
                slot_type,
                commitment: Some(Word::empty().into()),
            }],
        };

        let error = AccountStorageHeader::try_from(message).unwrap_err();
        assert_eq!(error.to_string(), format!("slots.slot_type: {expected_message}"));
    }
}

#[test]
fn account_storage_header_preserves_unknown_enum_value_source() {
    let error = AccountStorageHeader::try_from(proto::account::AccountStorageHeader {
        slots: vec![proto::account::account_storage_header::StorageSlot {
            slot_name: "miden::test::storage".into(),
            slot_type: i32::MAX,
            commitment: Some(Word::empty().into()),
        }],
    })
    .unwrap_err();

    assert!(matches!(
        error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<prost::UnknownEnumValue>()),
        Some(prost::UnknownEnumValue(value)) if *value == i32::MAX
    ));
}

#[test]
fn account_storage_header_uses_generated_slot_type_values() {
    for (slot_type, expected_slot_type) in [
        (StorageSlotType::Value, proto::account::StorageSlotType::Value),
        (StorageSlotType::Map, proto::account::StorageSlotType::Map),
    ] {
        let header = AccountStorageHeader::new(vec![StorageSlotHeader::new(
            StorageSlotName::new("miden::test::storage").unwrap(),
            slot_type,
            Word::empty(),
        )])
        .unwrap();

        let message = proto::account::AccountStorageHeader::from(&header);
        assert_eq!(message.slots[0].slot_type, expected_slot_type as i32);
        assert_eq!(AccountStorageHeader::try_from(message).unwrap(), header);
    }
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
fn empty_protobuf_block_body_decodes_to_an_empty_domain_body() {
    let expected =
        BlockBody::new(vec![], vec![], vec![], OrderedTransactionHeaders::new_unchecked(vec![]))
            .unwrap();

    assert_eq!(BlockBody::try_from(proto::blockchain::BlockBody::default()).unwrap(), expected);
}

#[test]
fn protobuf_block_body_rejects_created_nullifiers_missing_from_transactions() {
    let error = BlockBody::try_from(proto::blockchain::BlockBody {
        created_nullifiers: vec![Word::empty().into()],
        ..Default::default()
    })
    .unwrap_err();
    let source = error.source().unwrap().downcast_ref::<BlockBodyError>().unwrap();

    assert!(matches!(source, BlockBodyError::CreatedNullifiersMismatch));
}

#[test]
fn block_header_rejects_missing_block_number() {
    let header = BlockHeader::mock(1, None, None, &[], Word::empty());
    let mut message = proto::blockchain::BlockHeader::from(header);
    message.block_num = Default::default();

    let error = BlockHeader::try_from(message).unwrap_err();
    assert!(error.to_string().starts_with("block_num: field "));
    assert!(error.to_string().ends_with("::block_num is missing"));
}

#[test]
fn note_inclusion_proof_rejects_missing_block_number() {
    let message = proto::note::NoteInclusionProof {
        note_id: Some(Word::empty().into()),
        block_num: None,
        note_index_in_block: 0,
        inclusion_path: Some(proto::primitives::SparseMerklePath {
            empty_nodes_mask: 0,
            siblings: vec![],
        }),
    };

    let error = <(NoteId, NoteInclusionProof)>::try_from(&message).unwrap_err();
    assert_missing_block_number(error, "block_num");
}

#[test]
fn proven_transaction_rejects_missing_block_numbers() {
    let mut message = proven_transaction_data();
    message.reference_block_num = None;
    let error = ProvenTransaction::try_from(message).unwrap_err();
    assert_missing_block_number(error, "reference_block_num");

    let mut message = proven_transaction_data();
    message.expiration_block_num = None;
    let error = ProvenTransaction::try_from(message).unwrap_err();
    assert_missing_block_number(error, "expiration_block_num");
}

#[test]
fn proven_batch_rejects_missing_block_numbers() {
    let mut message = proven_batch_data();
    message.reference_block_num = None;
    let error = decode_standalone_proven_batch(message).unwrap_err();
    assert_missing_block_number(error, "reference_block_num");

    let mut message = proven_batch_data();
    message.expiration_block_num = None;
    let error = decode_standalone_proven_batch(message).unwrap_err();
    assert_missing_block_number(error, "expiration_block_num");
}

#[test]
fn transaction_header_conversion_preserves_validation_error_source() {
    let note = Note::mock_noop(Word::empty());
    let transaction = TransactionHeader::new(
        private_account_id(),
        Word::from([1_u32, 2, 3, 4]),
        Word::from([5_u32, 6, 7, 8]),
        InputNotes::default(),
        vec![*note.header()],
    )
    .unwrap();
    let mut message = proto::transaction::TransactionHeader::from(transaction);
    message.output_notes.push(message.output_notes[0].clone());

    let error = TransactionHeader::try_from(message).unwrap_err();
    let source = error.source().unwrap().downcast_ref::<TransactionHeaderError>().unwrap();

    assert!(matches!(
        source,
        TransactionHeaderError::DuplicateOutputNote(note_id) if *note_id == note.id()
    ));
}
