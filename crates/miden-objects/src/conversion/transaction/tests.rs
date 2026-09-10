use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::AccountUpdateDetails;
use miden_protocol::batch::BatchAccountUpdate;
use miden_protocol::note::{Note, NoteType, PartialNoteMetadata};
use miden_protocol::transaction::{PublicOutputNote, TransactionArgs};
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Word};
use prost::Message;

use crate::decoded::account::test_utils::private_account_id;
use crate::decoded::transaction::test_utils::note_id;
use crate::test_utils::dummy_word;
use crate::{DecodeMessage, Verify, proto};

fn public_note() -> Note {
    let (assets, metadata, recipient, attachments) = Note::mock_noop(Word::empty()).into_parts();
    let metadata =
        PartialNoteMetadata::new(metadata.sender(), NoteType::Public).with_tag(metadata.tag());

    Note::with_attachments(assets, metadata, recipient, attachments)
}

#[test]
fn public_output_note_roundtrips_through_protobuf() {
    let note = PublicOutputNote::new(public_note()).unwrap();

    let encoded = proto::transaction::PublicOutputNote::from(note.clone()).encode_to_vec();
    let message = proto::transaction::PublicOutputNote::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), note);
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
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), update);
}

#[test]
fn transaction_args_roundtrip_normalizes_note_args_order() {
    let first = note_id(1);
    let second = note_id(2);
    let args = TransactionArgs::from_parts(
        None,
        dummy_word(3),
        BTreeMap::from([(second, dummy_word(4)), (first, dummy_word(5))]),
        AdviceInputs::default().with_map([(dummy_word(6), vec![Felt::from(7_u32)])]),
        dummy_word(8),
    );

    let message = proto::transaction::TransactionArgs::from(&args);

    assert_eq!(
        message
            .note_args
            .iter()
            .map(|entry| entry.note_id.clone().unwrap().decode_fields().unwrap().verify().unwrap())
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), args);
}
