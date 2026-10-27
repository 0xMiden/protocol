use alloc::vec;

use miden_protocol::Word;
use miden_protocol::transaction::TransactionLog;

use super::*;

#[test]
fn bounded_decoder_checks_frames_and_resource_limits() {
    type WireBundle = proto::transaction::PublicTransactionLogBundle;
    let wire = WireBundle {
        transactions_commitment: Some(Word::empty().into()),
        entries: vec![proto::transaction::PublicTransactionLogEntry {
            transaction_id: Some(proto::transaction::TransactionId {
                id: Some(Word::empty().into()),
            }),
            logs: Some(proto::transaction::TransactionLogs {
                logs: vec![(&TransactionLog::mock(1)).into()],
            }),
        }],
    };
    let limits = TransactionLogBundleLimits {
        transactions: 1,
        logs: 1,
        content_words: 1,
    };
    let mut bytes = wire.encode_to_vec();
    bytes.extend_from_slice(&[0x1a, 0]); // Unknown field: skipped but charged to the byte limit.
    assert_eq!(WireBundle::decode_bounded(&bytes, limits, bytes.len()).unwrap(), wire);
    assert!(WireBundle::decode_bounded(&bytes, limits, bytes.len() - 1).is_err());
    for exhausted in [
        TransactionLogBundleLimits { transactions: 0, ..limits },
        TransactionLogBundleLimits { logs: 0, ..limits },
        TransactionLogBundleLimits { content_words: 0, ..limits },
    ] {
        assert!(WireBundle::decode_bounded(&bytes, exhausted, bytes.len()).is_err());
    }
    for invalid_frame in [
        &[0x12, 0x81, 0x80, 0x01][..], // Entry frame announces more than 16 KiB.
        &[0x12, 10],                   // Truncated entry frame.
    ] {
        assert!(
            WireBundle::decode_bounded(invalid_frame, limits, WireBundle::MAX_BATCH_BYTES).is_err()
        );
    }
    bytes.extend_from_slice(&wire.encode_to_vec()); // Duplicate commitment.
    assert!(WireBundle::decode_bounded(&bytes, limits, WireBundle::MAX_BATCH_BYTES).is_err());
}
