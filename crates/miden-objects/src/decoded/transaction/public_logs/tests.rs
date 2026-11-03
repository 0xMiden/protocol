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
        MAX_BATCH_LOG_BYTES
    } else {
        MAX_BLOCK_LOG_BYTES
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

fn entry(records: usize, words_per_record: usize) -> Vec<u8> {
    let record = frame(3, &[]).repeat(words_per_record);
    frame(1, &frame(2, &frame(1, &record).repeat(records)))
}

#[test]
fn embedded_logs_decode_entry_frame_limit() {
    // The entry contains only an unknown field, whose framing uses three bytes at this size.
    let exact = frame(1, &frame(15, &vec![0; MAX_LOG_ENTRY_BYTES - 3]));
    proto::blockchain::BlockBody::decode_bounded(&frame(5, &exact)).unwrap();
    let excessive = frame(1, &frame(15, &vec![0; MAX_LOG_ENTRY_BYTES - 2]));
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
    let oversized_body = frame(5, &frame(15, &vec![0; MAX_BLOCK_LOG_BYTES]));
    let error =
        proto::blockchain::SignedBlock::decode_bounded(&frame(2, &oversized_body)).unwrap_err();
    assert!(matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::PublicLogsLimitExceeded)
    ));
}
