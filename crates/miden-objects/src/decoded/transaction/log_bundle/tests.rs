use alloc::vec;

use miden_protocol::Word;
use miden_protocol::batch::BatchId;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
use miden_protocol::testing::dummy_execution_proof;
use miden_protocol::transaction::{InputNotes, TransactionHeader, TransactionLog};

use super::*;
use crate::{BuildUnchecked, DecodeMessageExt};

fn fixture() -> (ProvenBatch, BlockBody, VerifiedBundle) {
    let logs = TransactionLogs::new(vec![TransactionLog::mock(1); 2]).unwrap();
    let tx = TransactionHeader::new(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
        Word::from([1u32; 4]),
        Word::from([2u32; 4]),
        InputNotes::default(),
        vec![],
        logs.commitment(),
    )
    .unwrap();
    let entries = vec![(tx.id(), logs)];
    let headers = OrderedTransactionHeaders::new_unchecked(vec![tx]);
    let bundle = VerifiedBundle::new(entries, &headers).unwrap();
    let batch = ProvenBatch::new_unchecked(
        BatchId::from_ids(headers.as_slice().iter().map(|tx| (tx.id(), tx.account_id()))),
        Word::empty(),
        0.into(),
        Default::default(),
        InputNotes::default(),
        vec![],
        1.into(),
        headers.clone(),
        dummy_execution_proof(),
    )
    .unwrap();
    let body = BlockBody::new(vec![], vec![], vec![], headers).unwrap();
    (batch, body, bundle)
}

#[test]
fn detached_bundle_roundtrips_with_batch_and_block_context() {
    let (batch, body, bundle) = fixture();
    let wire = proto::transaction::PublicTransactionLogBundle::from(&bundle);
    let bytes = wire.encode_to_vec();
    assert_eq!(
        proto::transaction::PublicTransactionLogBundle::decode_for_batch(&bytes, &batch).unwrap(),
        bundle
    );
    assert_eq!(
        proto::transaction::PublicTransactionLogBundle::decode_for_block(&bytes, &body).unwrap(),
        bundle
    );
    assert_eq!(wire.decode_and_verify_with(&body).unwrap(), bundle);

    // The block round trip needs only headers, not the separately encoded bundle.
    let block_bytes = proto::blockchain::BlockBody::from(&body).encode_to_vec();
    let decoded = proto::blockchain::BlockBody::decode(block_bytes.as_slice())
        .unwrap()
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .unwrap();
    drop(bundle);
    assert_eq!(decoded, body);
    assert_ne!(decoded.transactions().as_slice()[0].logs_commitment(), Word::empty());
}

#[test]
fn bundle_decoder_rejects_tampering_and_missing_public_logs() {
    let (batch, body, bundle) = fixture();
    let wire = proto::transaction::PublicTransactionLogBundle::from(&bundle);
    for variant in 0..5 {
        let mut changed = wire.clone();
        match variant {
            0 => changed.transactions_commitment = Some(Word::empty().into()),
            1 => changed.entries.clear(),
            2 => changed.entries.push(changed.entries[0].clone()),
            3 => changed.entries[0].logs.as_mut().unwrap().logs[0].content.clear(),
            4 => {
                changed.entries[0].transaction_id.as_mut().unwrap().id = Some(Word::empty().into())
            },
            _ => unreachable!(),
        }
        let bytes = changed.encode_to_vec();
        assert!(
            proto::transaction::PublicTransactionLogBundle::decode_for_batch(&bytes, &batch)
                .is_err()
        );
        assert!(
            proto::transaction::PublicTransactionLogBundle::decode_for_block(&bytes, &body)
                .is_err()
        );
    }
}

#[test]
fn bundle_decoder_bounds_bytes_entries_and_frames_before_field_decoding() {
    type WireBundle = proto::transaction::PublicTransactionLogBundle;
    let limits = TransactionLogBundleLimits::BATCH;
    assert!(
        WireBundle::decode_bounded(
            &vec![0; WireBundle::MAX_BATCH_BYTES + 1],
            limits,
            WireBundle::MAX_BATCH_BYTES
        )
        .is_err()
    );
    // Repeated empty messages are small on the wire but must not cause unbounded allocations.
    let entries = [0x12, 0].repeat(limits.transactions + 1);
    assert!(WireBundle::decode_bounded(&entries, limits, WireBundle::MAX_BATCH_BYTES).is_err());
    // The next entry's announced frame exceeds 16 KiB; no payload allocation is needed to reject
    // it.
    assert!(
        WireBundle::decode_bounded(&[0x12, 0x81, 0x80, 0x01], limits, WireBundle::MAX_BATCH_BYTES)
            .is_err()
    );
    for truncated in [&[0x12][..], &[0x12, 10], &[0x0a, 1], &[0x12, 0xff]] {
        assert!(
            WireBundle::decode_bounded(truncated, limits, WireBundle::MAX_BATCH_BYTES).is_err()
        );
    }
}

#[test]
fn bundle_decoder_enforces_aggregate_and_transaction_log_limits() {
    type WireBundle = proto::transaction::PublicTransactionLogBundle;
    let (_, _, bundle) = fixture();
    let mut wire = WireBundle::from(&bundle);
    let logs = wire.entries[0].logs.as_mut().unwrap();
    let log = logs.logs[0].clone();
    logs.logs = vec![log; TransactionLogs::MAX_COUNT + 1];
    assert!(
        WireBundle::decode_bounded(
            &wire.encode_to_vec(),
            TransactionLogBundleLimits::BATCH,
            WireBundle::MAX_BATCH_BYTES
        )
        .is_err()
    );

    let mut wire = WireBundle::from(&bundle);
    let empty_log = proto::transaction::TransactionLog::from(&TransactionLog::mock(0));
    wire.entries[0].logs.as_mut().unwrap().logs = vec![empty_log; 64];
    wire.entries = vec![wire.entries[0].clone(); 64];
    assert!(
        WireBundle::decode_bounded(
            &wire.encode_to_vec(),
            TransactionLogBundleLimits::BATCH,
            WireBundle::MAX_BATCH_BYTES
        )
        .is_ok()
    );
    wire.entries.push(wire.entries[0].clone());
    assert!(
        WireBundle::decode_bounded(
            &wire.encode_to_vec(),
            TransactionLogBundleLimits::BATCH,
            WireBundle::MAX_BATCH_BYTES
        )
        .is_err()
    );
}

#[test]
fn bundle_decoder_counts_unknown_fields_and_rejects_duplicate_commitments() {
    type WireBundle = proto::transaction::PublicTransactionLogBundle;
    let (batch, _, bundle) = fixture();
    let wire = WireBundle::from(&bundle);
    let mut bytes = wire.encode_to_vec();
    // Unknown field 3 must be skipped but still charged to the byte budget.
    bytes.extend_from_slice(&[0x1a, 3, 1, 2, 3]);
    assert_eq!(WireBundle::decode_for_batch(&bytes, &batch).unwrap(), bundle);
    assert!(
        WireBundle::decode_bounded(&bytes, TransactionLogBundleLimits::BATCH, bytes.len()).is_ok()
    );
    assert!(
        WireBundle::decode_bounded(&bytes, TransactionLogBundleLimits::BATCH, bytes.len() - 1)
            .is_err()
    );

    let duplicate = WireBundle {
        transactions_commitment: wire.transactions_commitment,
        entries: vec![],
    };
    bytes.extend_from_slice(&duplicate.encode_to_vec());
    assert!(WireBundle::decode_for_batch(&bytes, &batch).is_err());
}
