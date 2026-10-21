use alloc::vec;

use assert_matches::assert_matches;
use miden_protocol::transaction::{TransactionLog, TransactionLogError, TransactionLogs};
use miden_protocol::{Felt, Word};
use prost::Message;

use crate::test_utils::error_source;
use crate::{DecodeMessage, Verify, proto};

#[test]
fn logs_roundtrip_preserves_duplicates() {
    let log = TransactionLog::mock(1);
    let logs = TransactionLogs::new(vec![log.clone(), log]).unwrap();
    let bytes = proto::transaction::TransactionLogs::from(&logs).encode_to_vec();
    let decoded = proto::transaction::TransactionLogs::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded.decode_fields().unwrap().verify().unwrap(), logs);
}

#[test]
fn logs_reject_excessive_counts_and_content() {
    let empty = proto::transaction::TransactionLog::from(&TransactionLog::mock(0));
    let oversized = proto::transaction::TransactionLogs {
        logs: vec![empty.clone(); TransactionLogs::MAX_COUNT + 1],
    };
    let error = oversized.decode_fields().unwrap().verify().unwrap_err();
    assert_matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::TooManyLogs(_))
    );

    let oversized = proto::transaction::TransactionLogs {
        logs: vec![proto::transaction::TransactionLog {
            content: vec![Word::empty().into(); TransactionLog::MAX_NUM_WORDS + 1],
            ..empty
        }],
    };
    let error = oversized.decode_fields().unwrap().verify().unwrap_err();
    assert_matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::TooManyContentWords(_))
    );

    let full = proto::transaction::TransactionLog::from(&TransactionLog::mock(
        TransactionLog::MAX_NUM_WORDS,
    ));
    let oversized = proto::transaction::TransactionLogs {
        logs: vec![full; TransactionLogs::MAX_NUM_WORDS / TransactionLog::MAX_NUM_WORDS + 1],
    };
    let error = oversized.decode_fields().unwrap().verify().unwrap_err();
    assert_matches!(
        error_source::<TransactionLogError>(&error),
        Some(TransactionLogError::TooManyTotalContentWords(_))
    );
}

#[test]
fn logs_require_visibility_and_canonical_topic_elements() {
    assert!(proto::transaction::TransactionLogDetails::default().decode_fields().is_err());
    let mut log = proto::transaction::TransactionLog::from(&TransactionLog::mock(1));
    log.topic.as_mut().unwrap().suffix = Some(proto::primitives::Felt { value: Felt::ORDER });
    assert!(log.decode_fields().is_err());
}
