use alloc::vec;

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, PartialNote};
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    RawOutputNote,
    RawOutputNotes,
    TransactionEffects,
};
use prost::Message;

use crate::decoded::account::test_utils::account_patch;
use crate::decoded::transaction::TransactionEffectsError;
use crate::test_utils::{dummy_word, error_source};
use crate::{DecodeMessage, Verify, proto};

fn transaction_effects() -> TransactionEffects {
    let input_notes =
        InputNotes::new(vec![InputNote::unauthenticated(Note::mock_noop(dummy_word(1)))]).unwrap();
    let output_notes = RawOutputNotes::new(vec![
        RawOutputNote::Full(Note::mock_noop(dummy_word(2))),
        RawOutputNote::Partial(PartialNote::from(Note::mock_noop(dummy_word(3)))),
    ])
    .unwrap();

    TransactionEffects::new(
        dummy_word(4),
        dummy_word(5),
        account_patch(),
        input_notes,
        output_notes,
        BlockNumber::from(17_u32),
        dummy_word(6),
        BlockNumber::from(42_u32),
    )
}

#[test]
fn transaction_effects_roundtrips_through_protobuf() {
    let effects = transaction_effects();

    let encoded = proto::transaction::TransactionEffects::from(&effects).encode_to_vec();
    let message = proto::transaction::TransactionEffects::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), effects);
}

#[test]
fn transaction_effects_reject_a_transaction_id_that_does_not_match_the_effects() {
    use proto::transaction::transaction_effects::Version;

    let effects = transaction_effects();
    let mut inner = proto::transaction::TransactionEffectsV1::from(&effects);
    inner.transaction_id =
        Some(proto::transaction::TransactionId { id: Some(dummy_word(99).into()) });
    let wire = proto::transaction::TransactionEffects { version: Some(Version::V1(inner)) };

    let error = wire.decode_fields().unwrap().verify().unwrap_err();
    let mismatch = error_source::<TransactionEffectsError>(&error).unwrap();

    assert!(matches!(mismatch, TransactionEffectsError::IdMismatch { recomputed, .. }
        if *recomputed == effects.transaction_id()));
}
