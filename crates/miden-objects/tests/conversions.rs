use core::error::Error;

use miden_objects::proto;
use miden_protocol::Word;
use miden_protocol::account::{
    AccountId,
    AccountIdVersion,
    AccountType,
    AccountUpdateDetails,
    AssetCallbackFlag,
};
use miden_protocol::batch::BatchAccountUpdate;
use miden_protocol::block::{BlockAccountUpdate, BlockBody};
use miden_protocol::errors::TransactionHeaderError;
use miden_protocol::note::Note;
use miden_protocol::transaction::{InputNotes, OrderedTransactionHeaders, TransactionHeader};
use prost::Message;

fn private_account_id() -> AccountId {
    AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
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
