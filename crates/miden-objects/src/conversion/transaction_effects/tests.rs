use alloc::vec;

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, PartialNote};
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    LogTopic,
    RawOutputNote,
    RawOutputNotes,
    TransactionEffects,
    TransactionLog,
    TransactionLogs,
};
use prost::Message;

use crate::decoded::account::test_utils::account_patch;
use crate::test_utils::dummy_word;
use crate::{DecodeMessage, Verify, proto};

fn transaction_effects() -> TransactionEffects {
    let account_patch = account_patch();
    let logs = TransactionLogs::new(vec![
        TransactionLog::new(
            account_patch.id(),
            LogTopic::from_name("test::updated"),
            vec![dummy_word(7)],
        )
        .unwrap(),
    ])
    .unwrap();
    let input_notes =
        InputNotes::new(vec![InputNote::unauthenticated(Note::mock_noop(dummy_word(1)))]).unwrap();
    let output_notes = RawOutputNotes::new(vec![
        RawOutputNote::Full(Note::mock_noop(dummy_word(2))),
        RawOutputNote::Partial(PartialNote::from(Note::mock_noop(dummy_word(3)))),
    ])
    .unwrap();

    TransactionEffects::builder()
        .initial_state_commitment(dummy_word(4))
        .final_state_commitment(dummy_word(5))
        .account_patch(account_patch)
        .input_notes(input_notes)
        .output_notes(output_notes)
        .ref_block_number(BlockNumber::from(17_u32))
        .ref_block_commitment(dummy_word(6))
        .expiration_block_num(BlockNumber::from(42_u32))
        .logs(logs)
        .build()
}

#[test]
fn transaction_effects_roundtrips_through_protobuf() {
    let effects = transaction_effects();

    let encoded = proto::transaction::TransactionEffects::from(&effects).encode_to_vec();
    let message = proto::transaction::TransactionEffects::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), effects);
}
