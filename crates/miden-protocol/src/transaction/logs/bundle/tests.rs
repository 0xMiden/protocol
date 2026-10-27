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
fn bundle_validates_public_transaction_logs() {
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
fn aggregation_binds_public_and_private_batches_in_order() {
    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let public = header(1, true, &logs);
    let first = headers(vec![public.clone()]);
    let second = headers(vec![header(2, false, &logs)]);
    let third = headers(vec![header(3, false, &logs)]);
    let a = PublicTransactionLogBundle::new(vec![(public.id(), logs.clone())], &first).unwrap();
    let b = PublicTransactionLogBundle::new(vec![], &second).unwrap();
    let c = PublicTransactionLogBundle::new(vec![], &third).unwrap();
    let batches = OrderedBatches::new(vec![batch(first), batch(second), batch(third)]);
    let combined =
        PublicTransactionLogBundle::from_batches(&batches, vec![a.clone(), b.clone(), c.clone()])
            .unwrap();
    assert_eq!(combined.entries(), &[(public.id(), logs)]);
    combined.validate_for_block(&batches.to_transactions()).unwrap();
    // Swapping even private-only bundles must fail, despite both having no public entries.
    assert!(PublicTransactionLogBundle::from_batches(&batches, vec![a, c, b]).is_err());
    assert!(PublicTransactionLogBundle::from_batches(&batches, vec![]).is_err());
}
