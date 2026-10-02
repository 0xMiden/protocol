use alloc::vec::Vec;

use prost::Message;

use super::common;
use crate::{BuildUnchecked, DecodeMessage, Verify, proto};

#[test]
fn transaction_inputs_roundtrip_preserves_all_nested_fields_and_ordered_collections() {
    let expected = common::dummy_transaction_inputs();
    let mut message = proto::transaction::TransactionInputs::from(&expected);
    let v1 = common::transaction_inputs_v1_mut(&mut message);

    let encoded_note_ids = v1
        .input_notes
        .as_ref()
        .unwrap()
        .notes
        .iter()
        .map(|note| match note.note.as_ref().unwrap() {
            proto::transaction::input_note::Note::Authenticated(note) => note
                .note
                .as_ref()
                .unwrap()
                .clone()
                .decode_fields()
                .unwrap()
                .verify()
                .unwrap()
                .id(),
            proto::transaction::input_note::Note::Unauthenticated(note) => {
                note.clone().decode_fields().unwrap().verify().unwrap().id()
            },
        })
        .collect::<Vec<_>>();
    assert_eq!(
        encoded_note_ids,
        expected.input_notes().iter().map(|note| note.id()).collect::<Vec<_>>()
    );

    v1.foreign_account_slot_names.reverse();
    let encoded = message.encode_to_vec();
    let decoded_message =
        proto::transaction::TransactionInputs::decode(encoded.as_slice()).unwrap();
    let actual = decoded_message.decode_fields().unwrap().build_unchecked().unwrap();

    assert_eq!(actual, expected);
    assert_eq!(actual.foreign_account_code(), expected.foreign_account_code());
    assert_eq!(
        actual.input_notes().iter().map(|note| note.id()).collect::<Vec<_>>(),
        expected.input_notes().iter().map(|note| note.id()).collect::<Vec<_>>()
    );

    let normalized = proto::transaction::TransactionInputs::from(&actual);
    let proto::transaction::transaction_inputs::Version::V1(normalized) =
        normalized.version.unwrap();
    let normalized_slot_ids = normalized
        .foreign_account_slot_names
        .iter()
        .map(|entry| entry.slot_id.unwrap())
        .collect::<Vec<_>>();
    assert!(normalized_slot_ids.windows(2).all(|ids| {
        ids[0].decode_fields().unwrap().verify().unwrap()
            < ids[1].decode_fields().unwrap().verify().unwrap()
    }));

    let decoded_code = actual.foreign_account_code();
    assert_ne!(decoded_code[0].commitment(), decoded_code[1].commitment());
}
