use core::error::Error;

use miden_objects::conversion::decode_standalone_proven_batch;
use miden_objects::{ConversionError, proto};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountId,
    AccountIdVersion,
    AccountType,
    AccountUpdateDetails,
    AssetCallbackFlag,
};
use miden_protocol::batch::BatchAccountUpdate;
use miden_protocol::block::{BlockAccountUpdate, BlockBody, BlockHeader};
use miden_protocol::errors::TransactionHeaderError;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof};
use miden_protocol::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
    ProvenTransaction,
    TransactionHeader,
    TxAccountUpdate,
};
use miden_protocol::vm::ExecutionProof;
use prost::Message;

fn private_account_id() -> AccountId {
    AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
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
