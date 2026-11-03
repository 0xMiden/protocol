use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::transaction::{PublicLogLimits, TransactionLogError};
use prost::encoding::{WireType, encode_key};
use rstest::rstest;

use super::*;
use crate::test_utils::error_source;

fn frame(tag: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_key(tag, WireType::LengthDelimited, &mut bytes);
    prost::encode_length_delimiter(payload.len(), &mut bytes).unwrap();
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn embedded_logs_decode_bounds() {
    // A present empty collection is required, even when there are no public transactions.
    let body = frame(5, &[]);
    assert!(
        proto::blockchain::BlockBody::decode_bounded(&body)
            .unwrap()
            .public_logs
            .is_some()
    );
    let error =
        proto::blockchain::BlockBody::decode_bounded(&[body.clone(), body].concat()).unwrap_err();
    assert!(matches!(
        error_source::<PublicLogDecodeError>(&error),
        Some(PublicLogDecodeError::DuplicateField("public_logs"))
    ));
}

#[rstest]
#[case::batch(true)]
#[case::block(false)]
fn embedded_logs_decode_byte_limits(#[case] batch: bool) {
    let cap = if batch {
        proto::transaction::ProvenBatch::MAX_LOG_BYTES
    } else {
        proto::blockchain::BlockBody::MAX_LOG_BYTES
    };
    let tag = if batch { 9 } else { 5 };
    // Five bytes of owner framing and five bytes of unknown-field framing at these sizes.
    let payload = frame(15, &vec![0; cap - 10]);
    let bytes = frame(tag, &payload);
    assert_eq!(bytes.len(), cap);
    if batch {
        proto::transaction::ProvenBatch::decode_bounded(&bytes).unwrap();
    } else {
        proto::blockchain::BlockBody::decode_bounded(&bytes).unwrap();
    }
    let oversized = frame(tag, &frame(15, &vec![0; cap - 9]));
    let error = if batch {
        proto::transaction::ProvenBatch::decode_bounded(&oversized).unwrap_err()
    } else {
        proto::blockchain::BlockBody::decode_bounded(&oversized).unwrap_err()
    };
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

#[test]
fn embedded_logs_decode_nested_body() {
    let body = frame(5, &[]);
    let signed = frame(2, &body);
    proto::blockchain::SignedBlock::decode_bounded(&signed).unwrap();
    let error = proto::blockchain::SignedBlock::decode_bounded(&[signed.clone(), signed].concat())
        .unwrap_err();
    assert!(matches!(
        error_source::<PublicLogDecodeError>(&error),
        Some(PublicLogDecodeError::DuplicateField("body"))
    ));
    let malformed_body = [body.clone(), body].concat();
    let error =
        proto::blockchain::SignedBlock::decode_bounded(&frame(2, &malformed_body)).unwrap_err();
    assert!(matches!(
        error_source::<PublicLogDecodeError>(&error),
        Some(PublicLogDecodeError::DuplicateField("public_logs"))
    ));
}

#[rstest]
#[case::truncated(vec![0x2a, 10], true)]
#[case::wrong_wire(vec![0x28, 0], false)]
fn embedded_logs_decode_malformed_frames(#[case] bytes: Vec<u8>, #[case] truncated: bool) {
    let error = proto::blockchain::BlockBody::decode_bounded(&bytes).unwrap_err();
    if truncated {
        assert!(matches!(
            error_source::<PublicLogDecodeError>(&error),
            Some(PublicLogDecodeError::TruncatedFrame)
        ));
    } else {
        assert!(error_source::<prost::DecodeError>(&error).is_some(), "{error}");
    }
}

#[rstest]
#[case::headers_first(true)]
#[case::logs_first(false)]
fn embedded_logs_decode_counts_headers_in_any_order(#[case] headers_first: bool) {
    let headers = frame(7, &[]).repeat(PublicLogLimits::BATCH.transactions() + 1);
    let logs = frame(9, &[]);
    let bytes = if headers_first {
        [headers, logs].concat()
    } else {
        [logs, headers].concat()
    };
    let error = proto::transaction::ProvenBatch::decode_bounded(&bytes).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

#[rstest]
#[case::body_headers_first(false, true)]
#[case::body_logs_first(false, false)]
#[case::signed_headers_first(true, true)]
#[case::signed_logs_first(true, false)]
fn embedded_logs_decode_counts_headers_across_batches(
    #[case] signed: bool,
    #[case] headers_first: bool,
) {
    let half = frame(1, &[]).repeat(PublicLogLimits::BLOCK.transactions() / 2);
    let headers = frame(4, &half).repeat(2);
    let logs = frame(5, &[]);
    let decode = |headers: Vec<u8>| {
        let body = if headers_first {
            [headers, logs.clone()].concat()
        } else {
            [logs.clone(), headers].concat()
        };
        if signed {
            proto::blockchain::SignedBlock::decode_bounded(&frame(2, &body)).map(|_| ())
        } else {
            proto::blockchain::BlockBody::decode_bounded(&body).map(|_| ())
        }
    };
    decode(headers.clone()).unwrap();
    let error = decode([headers, frame(4, &frame(1, &[]))].concat()).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

#[test]
fn embedded_logs_decode_bounds_empty_batch_groups() {
    let mut body = frame(4, &[]).repeat(miden_protocol::MAX_BATCHES_PER_BLOCK);
    body.extend(frame(5, &[]));
    proto::blockchain::BlockBody::decode_bounded(&body).unwrap();
    body.extend(frame(4, &[]));
    let error = proto::blockchain::BlockBody::decode_bounded(&body).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

fn entry(records: usize, words_per_record: usize) -> Vec<u8> {
    let record = frame(3, &[]).repeat(words_per_record);
    frame(1, &frame(2, &frame(1, &record).repeat(records)))
}

#[test]
fn embedded_logs_decode_entry_frame_limit() {
    // The entry contains only an unknown field, whose framing uses three bytes at this size.
    let exact = frame(
        1,
        &frame(15, &vec![0; proto::transaction::PublicTransactionLogEntry::MAX_BYTES - 3]),
    );
    proto::blockchain::BlockBody::decode_bounded(&frame(5, &exact)).unwrap();
    let excessive = frame(
        1,
        &frame(15, &vec![0; proto::transaction::PublicTransactionLogEntry::MAX_BYTES - 2]),
    );
    let error = proto::blockchain::BlockBody::decode_bounded(&frame(5, &excessive)).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

#[rstest]
#[case::records(entry(65, 0), 0)]
#[case::per_log_words(entry(1, 65), 1)]
#[case::per_tx_words(entry(2, 33), 2)]
fn embedded_logs_decode_transaction_budgets(#[case] logs: Vec<u8>, #[case] kind: u8) {
    let error = proto::blockchain::BlockBody::decode_bounded(&frame(5, &logs)).unwrap_err();
    let source = error_source::<TransactionLogError>(&error).unwrap();
    match kind {
        0 => assert!(matches!(source, TransactionLogError::TooManyLogs(65))),
        1 => assert!(matches!(source, TransactionLogError::TooManyContentWords(65))),
        2 => assert!(matches!(source, TransactionLogError::TooManyTotalContentWords(65))),
        _ => unreachable!(),
    }
}

#[rstest]
#[case::batch_entries(true, 0)]
#[case::batch_records(true, 1)]
#[case::block_records(false, 1)]
#[case::block_words(false, 2)]
fn embedded_logs_decode_aggregate_budgets(#[case] batch: bool, #[case] kind: u8) {
    let limits = if batch {
        PublicLogLimits::BATCH
    } else {
        PublicLogLimits::BLOCK
    };
    let (one, count) = match kind {
        0 => (frame(1, &[]), limits.transactions()),
        1 => (entry(64, 0), limits.logs() / 64),
        2 => (entry(1, 64), limits.content_words() / 64),
        _ => unreachable!(),
    };
    let mut logs = one.repeat(count);
    let decode = |logs: &[u8]| -> Result<(), VerificationError> {
        if batch {
            proto::transaction::ProvenBatch::decode_bounded(&frame(9, logs)).map(|_| ())
        } else {
            proto::blockchain::BlockBody::decode_bounded(&frame(5, logs)).map(|_| ())
        }
    };
    decode(&logs).unwrap();
    logs.extend_from_slice(&one);
    let error = decode(&logs).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

#[test]
fn embedded_logs_decode_rejects_merged_entry_lists() {
    let duplicate = frame(1, &[frame(2, &[]), frame(2, &[])].concat());
    let error = proto::blockchain::BlockBody::decode_bounded(&frame(5, &duplicate)).unwrap_err();
    assert!(matches!(
        error_source::<PublicLogDecodeError>(&error),
        Some(PublicLogDecodeError::DuplicateField("entry.logs"))
    ));
}

#[test]
fn embedded_logs_decode_exhaustion_precedes_next_record_frame() {
    let mut logs = entry(64, 0).repeat(PublicLogLimits::BATCH.logs() / 64);
    // Another record tag, but no length: exhaustion must win before its frame is read.
    logs.extend(frame(1, &frame(2, &[0x0a])));
    let error = proto::transaction::ProvenBatch::decode_bounded(&frame(9, &logs)).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

#[test]
fn embedded_logs_decode_exhaustion_precedes_next_word_frame() {
    let mut logs = entry(1, 64).repeat(PublicLogLimits::BLOCK.content_words() / 64);
    logs.extend(frame(1, &frame(2, &frame(1, &[0x1a]))));
    let error = proto::blockchain::BlockBody::decode_bounded(&frame(5, &logs)).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

#[test]
fn embedded_logs_decode_nested_body_size_limit() {
    let oversized_body =
        frame(5, &frame(15, &vec![0; proto::blockchain::BlockBody::MAX_LOG_BYTES]));
    let error =
        proto::blockchain::SignedBlock::decode_bounded(&frame(2, &oversized_body)).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}

fn logged_owners() -> (miden_protocol::batch::ProvenBatch, miden_protocol::block::BlockBody) {
    use miden_protocol::Word;
    use miden_protocol::account::{AccountId, AccountPatch, AccountUpdateDetails};
    use miden_protocol::batch::{BatchAccountUpdate, ProvenBatch};
    use miden_protocol::block::BlockBody;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };
    use miden_protocol::testing::dummy_execution_proof;
    use miden_protocol::transaction::{
        InputNotes,
        OrderedTransactionHeaders,
        PublicTransactionLogs,
        TransactionHeader,
        TransactionLog,
        TransactionLogs,
    };
    let public: AccountId = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
    let private: AccountId = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    let log = TransactionLog::mock(1);
    let logs = TransactionLogs::new(vec![log.clone(), log]).unwrap();
    let headers = OrderedTransactionHeaders::new_unchecked(vec![
        TransactionHeader::new(
            public,
            Word::from([1u32; 4]),
            Word::from([2u32; 4]),
            InputNotes::default(),
            vec![],
            logs.commitment(),
        )
        .unwrap(),
        TransactionHeader::new(
            private,
            Word::from([4u32; 4]),
            Word::from([5u32; 4]),
            InputNotes::default(),
            vec![],
            Word::from([99u32; 4]),
        )
        .unwrap(),
        TransactionHeader::new(
            public,
            Word::from([2u32; 4]),
            Word::from([3u32; 4]),
            InputNotes::default(),
            vec![],
            Word::empty(),
        )
        .unwrap(),
    ]);
    let public_logs = PublicTransactionLogs::new(
        vec![
            (headers.as_slice()[0].id(), logs),
            (headers.as_slice()[2].id(), TransactionLogs::default()),
        ],
        &headers,
    )
    .unwrap();
    let updates = vec![
        BatchAccountUpdate::new(
            public,
            Word::from([1u32; 4]),
            Word::from([3u32; 4]),
            AccountUpdateDetails::Public(AccountPatch::empty(public)),
        )
        .unwrap(),
        BatchAccountUpdate::new(
            private,
            Word::from([4u32; 4]),
            Word::from([5u32; 4]),
            AccountUpdateDetails::Private,
        )
        .unwrap(),
    ];
    let batch = ProvenBatch::new(
        Word::empty(),
        0.into(),
        updates,
        InputNotes::default(),
        vec![],
        1.into(),
        headers.clone(),
        public_logs.clone(),
        dummy_execution_proof(),
    )
    .unwrap();
    let grouped_headers = vec![
        OrderedTransactionHeaders::new_unchecked(headers.as_slice()[..2].to_vec()),
        OrderedTransactionHeaders::new_unchecked(headers.as_slice()[2..].to_vec()),
    ];
    let body = BlockBody::new(vec![], vec![], vec![], grouped_headers, public_logs).unwrap();
    (batch, body)
}

#[test]
fn embedded_logs_roundtrip_preserves_mixed_owners() {
    use prost::Message;

    use crate::DecodeMessageExt;
    let (batch, body) = logged_owners();
    let wire = proto::transaction::ProvenBatch::from(&batch);
    let decoded = proto::transaction::ProvenBatch::decode_bounded(&wire.encode_to_vec())
        .unwrap()
        .decode_and_build_unchecked()
        .unwrap();
    assert_eq!(batch, decoded);
    let wire = proto::blockchain::BlockBody::from(&body);
    let decoded = proto::blockchain::BlockBody::decode_bounded(&wire.encode_to_vec())
        .unwrap()
        .decode_and_build_unchecked()
        .unwrap();
    assert_eq!(body, decoded);
    let entries = &wire.public_logs.unwrap().entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].logs.as_ref().unwrap().logs.len(), 2);
    assert!(entries[1].logs.as_ref().unwrap().logs.is_empty());
    // A private transaction's commitment stays in its header and has no payload entry.
    assert!(entries.iter().all(
        |entry| entry.transaction_id != Some(body.transactions()[0].as_slice()[1].id().into())
    ));
}

#[rstest]
#[case::missing(0)]
#[case::missing_empty(1)]
#[case::reordered(2)]
#[case::duplicated(3)]
#[case::private_entry(4)]
#[case::content_changed(5)]
fn tampered_embedded_logs_are_rejected(#[case] mutation: u8) {
    use prost::Message;

    use crate::DecodeMessageExt;
    let (batch, body) = logged_owners();
    let mut wire_batch = proto::transaction::ProvenBatch::from(&batch);
    let entries = &mut wire_batch.public_logs.as_mut().unwrap().entries;
    match mutation {
        0 => entries.clear(),
        1 => {
            entries.pop();
        },
        2 => entries.swap(0, 1),
        3 => entries[1] = entries[0].clone(),
        4 => {
            let mut entry = entries[0].clone();
            entry.transaction_id = Some(batch.transactions().as_slice()[1].id().into());
            entries.insert(1, entry);
        },
        5 => entries[0].logs.as_mut().unwrap().logs[0].content.clear(),
        _ => unreachable!(),
    }
    let mut wire_body = proto::blockchain::BlockBody::from(&body);
    wire_body.public_logs = wire_batch.public_logs.clone();
    let errors = [
        proto::transaction::ProvenBatch::decode_bounded(&wire_batch.encode_to_vec())
            .unwrap()
            .decode_and_build_unchecked()
            .unwrap_err(),
        proto::blockchain::BlockBody::decode_bounded(&wire_body.encode_to_vec())
            .unwrap()
            .decode_and_build_unchecked()
            .unwrap_err(),
    ];
    for error in errors {
        let source = error_source::<TransactionLogError>(&error).unwrap();
        if mutation == 5 {
            assert!(matches!(source, TransactionLogError::PublicLogsCommitmentMismatch));
        } else {
            assert!(matches!(source, TransactionLogError::PublicLogsAssociationMismatch));
        }
    }
}

#[test]
fn checked_owners_revalidate_public_log_associations() {
    use miden_protocol::batch::ProvenBatch;
    use miden_protocol::block::BlockBody;
    use miden_protocol::errors::{BlockBodyError, ProvenBatchError};
    use miden_protocol::transaction::PublicTransactionLogs;
    let (batch, body) = logged_owners();
    // An empty collection is valid in isolation but not for these public headers.
    let result = BlockBody::new(
        vec![],
        vec![],
        vec![],
        body.transactions().to_vec(),
        PublicTransactionLogs::default(),
    );
    assert!(matches!(
        result,
        Err(BlockBodyError::TransactionLogs(
            TransactionLogError::PublicLogsAssociationMismatch
        ))
    ));
    let result = ProvenBatch::new(
        batch.reference_block_commitment(),
        batch.reference_block_num(),
        batch.account_updates().values().cloned(),
        batch.input_notes().clone(),
        batch.output_notes().to_vec(),
        batch.batch_expiration_block_num(),
        batch.transactions().clone(),
        PublicTransactionLogs::default(),
        batch.proof().clone(),
    );
    assert!(matches!(
        result,
        Err(ProvenBatchError::TransactionLogs(
            TransactionLogError::PublicLogsAssociationMismatch
        ))
    ));
}
