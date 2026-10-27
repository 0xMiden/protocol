use super::*;
use crate::batch::ProvenBatch;
use crate::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
};
use crate::testing::dummy_execution_proof;
use crate::transaction::{InputNotes, TransactionHeader, TransactionLog};

fn header(seed: u32, public: bool, logs: &TransactionLogs) -> TransactionHeader {
    TransactionHeader::new(
        if public {
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE
        } else {
            ACCOUNT_ID_PRIVATE_SENDER
        }
        .try_into()
        .unwrap(),
        Word::from([seed; 4]),
        Word::from([seed + 1; 4]),
        InputNotes::default(),
        vec![],
        logs.commitment(),
    )
    .unwrap()
}

fn headers(values: Vec<TransactionHeader>) -> OrderedTransactionHeaders {
    OrderedTransactionHeaders::new_unchecked(values)
}

fn batch(headers: OrderedTransactionHeaders) -> ProvenBatch {
    ProvenBatch::new_unchecked(
        crate::batch::BatchId::from_ids(
            headers.as_slice().iter().map(|tx| (tx.id(), tx.account_id())),
        ),
        Word::empty(),
        0.into(),
        Default::default(),
        InputNotes::default(),
        vec![],
        1.into(),
        headers,
        dummy_execution_proof(),
    )
    .unwrap()
}

#[test]
fn bundle_requires_every_public_transaction_in_order_and_preserves_duplicate_logs() {
    // An emitter's privacy does not determine the native transaction's visibility (FPI).
    let log = TransactionLog::mock(1);
    let logs = TransactionLogs::new(vec![log.clone(), log]).unwrap();
    let public = header(1, true, &logs);
    let private = header(2, false, &logs);
    let empty = header(3, true, &TransactionLogs::default());
    let entries = vec![(public.id(), logs.clone()), (empty.id(), TransactionLogs::default())];
    let all = headers(vec![public.clone(), private.clone(), empty.clone()]);
    let bundle = PublicTransactionLogBundle::new(entries.clone(), &all).unwrap();
    assert_eq!(bundle.entries(), entries);
    assert_eq!(bundle.transactions_commitment(), all.commitment());
    bundle.validate_for_batch(&all).unwrap();

    for invalid in [
        vec![],
        vec![entries[0].clone()], // Missing the public transaction with no logs.
        vec![entries[1].clone(), entries[0].clone()],
        vec![entries[0].clone(), entries[0].clone()],
        vec![entries[0].clone(), (private.id(), logs.clone()), entries[1].clone()],
    ] {
        assert!(matches!(
            PublicTransactionLogBundle::new(invalid, &all),
            Err(TransactionLogError::BundleAssociationMismatch)
        ));
    }
    assert!(matches!(
        PublicTransactionLogBundle::new(
            vec![(public.id(), TransactionLogs::default()), entries[1].clone()],
            &all,
        ),
        Err(TransactionLogError::BundleCommitmentMismatch)
    ));
    let changed_private = header(9, false, &logs);
    assert!(matches!(
        bundle.validate_for_block(&headers(vec![public, changed_private, empty])),
        Err(TransactionLogError::BundleCommitmentMismatch)
    ));
}

#[test]
fn bundle_binds_private_only_batches_and_checks_batch_order() {
    let first = headers(vec![header(1, false, &TransactionLogs::default())]);
    let second = headers(vec![header(2, false, &TransactionLogs::default())]);
    let a = PublicTransactionLogBundle::new(vec![], &first).unwrap();
    let b = PublicTransactionLogBundle::new(vec![], &second).unwrap();
    let batches = OrderedBatches::new(vec![batch(first), batch(second)]);
    let combined =
        PublicTransactionLogBundle::from_batches(&batches, vec![a.clone(), b.clone()]).unwrap();
    assert!(combined.entries().is_empty());
    combined.validate_for_block(&batches.to_transactions()).unwrap();
    assert!(PublicTransactionLogBundle::from_batches(&batches, vec![b, a]).is_err());
    assert!(PublicTransactionLogBundle::from_batches(&batches, vec![]).is_err());
}

#[test]
fn aggregation_preserves_public_transaction_and_emission_order() {
    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let a = header(1, true, &logs);
    let b = header(2, true, &TransactionLogs::default());
    let first = headers(vec![a.clone(), header(3, false, &logs)]);
    let second = headers(vec![b.clone()]);
    let bundles = vec![
        PublicTransactionLogBundle::new(vec![(a.id(), logs.clone())], &first).unwrap(),
        PublicTransactionLogBundle::new(vec![(b.id(), TransactionLogs::default())], &second)
            .unwrap(),
    ];
    let block = PublicTransactionLogBundle::from_batches(
        &OrderedBatches::new(vec![batch(first), batch(second)]),
        bundles,
    )
    .unwrap();
    assert_eq!(block.entries(), &[(a.id(), logs), (b.id(), TransactionLogs::default())]);
}

#[test]
fn bundle_limits_count_private_transactions_and_empty_log_content() {
    let empty = TransactionLogs::default();
    let all = headers((0..1024).map(|seed| header(seed, false, &empty)).collect());
    let bundle = PublicTransactionLogBundle::new(vec![], &all).unwrap();
    bundle.validate_for_batch(&all).unwrap();
    let over = headers((0..1025).map(|seed| header(seed, false, &empty)).collect());
    let bundle = PublicTransactionLogBundle::new(vec![], &over).unwrap();
    assert!(matches!(
        bundle.validate_for_batch(&over),
        Err(TransactionLogError::BundleLimitExceeded)
    ));

    let full =
        TransactionLogs::new(vec![TransactionLog::mock(0); TransactionLogs::MAX_COUNT]).unwrap();
    let mut all = (0..64).map(|seed| header(seed, true, &full)).collect::<Vec<_>>();
    let mut entries = all.iter().map(|tx| (tx.id(), full.clone())).collect::<Vec<_>>();
    let at_limit = headers(all.clone());
    PublicTransactionLogBundle::new(entries.clone(), &at_limit)
        .unwrap()
        .validate_for_batch(&at_limit)
        .unwrap();
    let extra = TransactionLogs::new(vec![TransactionLog::mock(0)]).unwrap();
    let tx = header(64, true, &extra);
    entries.push((tx.id(), extra));
    all.push(tx);
    let over = headers(all);
    assert!(matches!(
        PublicTransactionLogBundle::new(entries, &over)
            .unwrap()
            .validate_for_batch(&over),
        Err(TransactionLogError::BundleLimitExceeded)
    ));
}

#[test]
fn changing_logs_changes_transaction_batch_and_block_commitments() {
    let a = header(1, true, &TransactionLogs::default());
    let b = header(1, true, &TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap());
    assert_ne!(a.id(), b.id());
    let a = batch(headers(vec![a]));
    let b = batch(headers(vec![b]));
    assert_ne!(a.id(), b.id());
    assert_ne!(
        OrderedBatches::new(vec![a]).to_transactions().commitment(),
        OrderedBatches::new(vec![b]).to_transactions().commitment()
    );
}

#[test]
fn block_bundle_enforces_the_aggregate_content_budget() {
    let logs =
        TransactionLogs::new(vec![TransactionLog::mock(TransactionLogs::MAX_NUM_WORDS)]).unwrap();
    let count = TransactionLogBundleLimits::BLOCK.content_words / TransactionLogs::MAX_NUM_WORDS;
    let mut all = (0..count as u32).map(|seed| header(seed, true, &logs)).collect::<Vec<_>>();
    let mut entries = all.iter().map(|tx| (tx.id(), logs.clone())).collect::<Vec<_>>();
    PublicTransactionLogBundle::new(entries.clone(), &headers(all.clone())).unwrap();
    let extra = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let tx = header(count as u32, true, &extra);
    entries.push((tx.id(), extra));
    all.push(tx);
    assert!(matches!(
        PublicTransactionLogBundle::new(entries, &headers(all)),
        Err(TransactionLogError::BundleLimitExceeded)
    ));
}
