use alloc::vec;

use miden_protocol::Word;
use miden_protocol::account::AccountUpdateDetails;
use miden_protocol::block::{BlockAccountUpdate, BlockBody, BlockHeader};
use miden_protocol::transaction::{InputNotes, OrderedTransactionHeaders, TransactionHeader};
use prost::Message;

use crate::decoded::account::test_utils::private_account_id;
use crate::decoded::blockchain::test_utils::block_header_with_scheduled_upgrade;
use crate::{BuildUnchecked, DecodeMessage, proto};

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
    assert_eq!(message.decode_fields().unwrap().build_unchecked().unwrap(), body);
}

#[test]
fn block_header_protobuf_round_trip_preserves_current_fields() {
    let header = block_header_with_scheduled_upgrade();

    let encoded = proto::blockchain::BlockHeader::from(&header).encode_to_vec();
    let message = proto::blockchain::BlockHeader::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.version, proto::blockchain::BlockVersion::V1 as i32);
    assert_eq!(message.decode_fields().unwrap().build_unchecked().unwrap(), header);
}

#[test]
fn block_header_protobuf_round_trip_preserves_absent_scheduled_upgrade() {
    let header = BlockHeader::mock(1, None, None, &[]);
    assert!(header.next_protocol_config().is_none());

    let encoded = proto::blockchain::BlockHeader::from(&header).encode_to_vec();
    let message = proto::blockchain::BlockHeader::decode(encoded.as_slice()).unwrap();

    assert!(message.next_protocol_config.is_none());
    assert_eq!(message.decode_fields().unwrap().build_unchecked().unwrap(), header);
}
