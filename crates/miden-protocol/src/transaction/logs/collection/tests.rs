use assert_matches::assert_matches;
use rstest::rstest;

use crate::Word;
use crate::account::AccountId;
use crate::block::BlockBody;
use crate::errors::BlockBodyError;
use crate::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use crate::transaction::logs::collection::LogDataScope;
use crate::transaction::{
    InputNotes,
    LogTopic,
    OrderedTransactionHeaders,
    TransactionHeader,
    TransactionLog,
    TransactionLogDetails,
    TransactionLogDetailsCollection,
    TransactionLogError,
    TransactionLogs,
};

fn public_log(words: usize) -> TransactionLog {
    TransactionLog::new(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        LogTopic::from_name("test::updated"),
        vec![Word::from([17u32; 4]); words],
    )
    .unwrap()
}

fn header(account: AccountId, data: &TransactionLogDetails, state: u32) -> TransactionHeader {
    TransactionHeader::new(
        account,
        Word::from([state; 4]),
        Word::from([state + 1; 4]),
        InputNotes::default(),
        vec![],
        data.to_commitment(),
    )
    .unwrap()
}

#[test]
fn block_transaction_logs_validate_associations() {
    let public = TransactionLogDetails::Public(
        TransactionLogs::new(vec![public_log(1), public_log(1)]).unwrap(),
    );
    let private = TransactionLogDetails::Private(Word::from([73u32; 4]));
    let headers = OrderedTransactionHeaders::new_unchecked(vec![
        header(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(), &public, 1),
        header(ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(), &private, 3),
    ]);
    let data = TransactionLogDetailsCollection::new(vec![public.clone(), private.clone()]).unwrap();
    let block = BlockBody::new(vec![], vec![], vec![], data.clone(), headers.clone()).unwrap();
    assert_eq!(block.log_details(), &data);
    for entries in [
        vec![],
        vec![public.clone()],
        vec![public.clone(), private.clone(), private.clone()],
    ] {
        let invalid = TransactionLogDetailsCollection::new(entries).unwrap();
        assert!(matches!(
            BlockBody::new(vec![], vec![], vec![], invalid, headers.clone()),
            Err(BlockBodyError::LogData(TransactionLogError::AssociationCount))
        ));
    }
    let reversed = TransactionLogDetailsCollection::new(vec![private, public]).unwrap();
    assert_matches!(
        reversed.validate_for_block(&headers),
        Err(TransactionLogError::VisibilityMismatch)
    );

    let changed = TransactionLogDetailsCollection::new(vec![
        TransactionLogDetails::Public(TransactionLogs::new(vec![public_log(2)]).unwrap()),
        data.as_slice()[1].clone(),
    ])
    .unwrap();
    assert_matches!(
        changed.validate_for_block(&headers),
        Err(TransactionLogError::CommitmentMismatch(0))
    );
    let duplicate_headers =
        OrderedTransactionHeaders::new_unchecked(vec![headers.as_slice()[0].clone(); 2]);
    let duplicate_data =
        TransactionLogDetailsCollection::new(vec![data.as_slice()[0].clone(); 2]).unwrap();
    assert!(BlockBody::new(vec![], vec![], vec![], duplicate_data, duplicate_headers).is_err());
}

#[rstest]
#[case::batch(LogDataScope::Batch)]
#[case::block(LogDataScope::Block)]
fn payload_word_limit_accepts_the_boundary_and_rejects_one_more(#[case] scope: LogDataScope) {
    let entry = TransactionLogDetails::Public(
        TransactionLogs::new(vec![
            public_log(TransactionLog::MAX_NUM_WORDS);
            TransactionLogs::MAX_NUM_WORDS / TransactionLog::MAX_NUM_WORDS
        ])
        .unwrap(),
    );
    let extra = TransactionLogDetails::Public(TransactionLogs::new(vec![public_log(1)]).unwrap());
    let count = scope.budget().payload_words / TransactionLogs::MAX_NUM_WORDS;
    assert_aggregate_limit(scope, entry, count, extra);
}

#[rstest]
#[case::batch(LogDataScope::Batch)]
#[case::block(LogDataScope::Block)]
fn public_transaction_log_limit_accepts_the_boundary_and_rejects_one_more(
    #[case] scope: LogDataScope,
) {
    let entry = TransactionLogDetails::Public(
        TransactionLogs::new(vec![public_log(0); TransactionLogs::MAX_COUNT]).unwrap(),
    );
    let extra = TransactionLogDetails::Public(TransactionLogs::new(vec![public_log(0)]).unwrap());
    let count = scope.budget().public_logs / TransactionLogs::MAX_COUNT;
    assert_aggregate_limit(scope, entry, count, extra);
}

#[rstest]
#[case::batch_public(
    LogDataScope::Batch,
    TransactionLogDetails::Public(TransactionLogs::default())
)]
#[case::batch_private(LogDataScope::Batch, TransactionLogDetails::Private(Word::empty()))]
#[case::block_public(
    LogDataScope::Block,
    TransactionLogDetails::Public(TransactionLogs::default())
)]
#[case::block_private(LogDataScope::Block, TransactionLogDetails::Private(Word::empty()))]
fn transaction_entry_limit_includes_empty_and_private_entries(
    #[case] scope: LogDataScope,
    #[case] entry: TransactionLogDetails,
) {
    assert_aggregate_limit(scope, entry.clone(), scope.budget().entries, entry);
}

fn assert_aggregate_limit(
    scope: LogDataScope,
    entry: TransactionLogDetails,
    count: usize,
    extra: TransactionLogDetails,
) {
    let mut entries = vec![entry; count];
    assert!(TransactionLogDetailsCollection::validate_budget(entries.iter(), scope).is_ok());
    TransactionLogDetailsCollection::new(entries.clone()).unwrap();

    entries.push(extra);
    assert_matches!(
        TransactionLogDetailsCollection::validate_budget(entries.iter(), scope),
        Err(TransactionLogError::AggregateBudget)
    );
}
