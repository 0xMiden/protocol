use assert_matches::assert_matches;
use rstest::rstest;

use super::*;
use crate::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
};

#[test]
fn empty_collection() {
    let logs = TransactionLogs::default();
    assert_eq!(logs, TransactionLogs::new(vec![]).unwrap());
    assert!(logs.is_empty());
    assert_eq!(logs.num_logs(), 0);
    assert_eq!(logs.num_content_words(), 0);
    assert_eq!(logs.commitment(), Word::empty());
}

#[test]
fn empty_content_is_not_an_absent_log_or_zero_word_content() {
    let empty_content = TransactionLog::mock(0);
    assert_eq!(empty_content.content_commitment(), Word::empty());

    let mut zero_word_content = empty_content.clone();
    zero_word_content.content.push(Word::empty());
    assert_ne!(zero_word_content.content_commitment(), Word::empty());

    let logs = TransactionLogs::new(vec![empty_content]).unwrap();
    assert!(!logs.is_empty());
    assert_ne!(logs.commitment(), Word::empty());
    assert_ne!(
        logs.commitment(),
        TransactionLogs::new(vec![zero_word_content]).unwrap().commitment()
    );
}

#[test]
fn constructors_reject_excessive_sizes() {
    assert_matches!(
        TransactionLog::new(
            ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
            LogTopic::mock(0, 0),
            vec![Word::empty(); TransactionLog::MAX_NUM_WORDS + 1],
        )
        .unwrap_err(),
        TransactionLogError::TooManyContentWords(count) if count == TransactionLog::MAX_NUM_WORDS + 1
    );
    assert_matches!(
        TransactionLogs::new(vec![TransactionLog::mock(0); TransactionLogs::MAX_COUNT + 1]).unwrap_err(),
        TransactionLogError::TooManyLogs(count) if count == TransactionLogs::MAX_COUNT + 1
    );

    let mut entries = vec![
        TransactionLog::mock(TransactionLog::MAX_NUM_WORDS);
        TransactionLogs::MAX_NUM_WORDS / TransactionLog::MAX_NUM_WORDS
    ];
    entries.push(TransactionLog::mock(1));
    assert_matches!(
        TransactionLogs::new(entries).unwrap_err(),
        TransactionLogError::TooManyTotalContentWords(count) if count == TransactionLogs::MAX_NUM_WORDS + 1
    );
}

#[rstest]
#[case::single_log(1, TransactionLog::MAX_NUM_WORDS)]
#[case::two_logs(2, TransactionLogs::MAX_NUM_WORDS / 2)]
#[case::one_word_logs(TransactionLogs::MAX_COUNT, 1)]
fn constructors_accept_maximum_content(#[case] count: usize, #[case] num_words: usize) {
    TransactionLogs::new(vec![TransactionLog::mock(num_words); count]).unwrap();
}

#[test]
fn private_log_details_have_no_commitment_preimage() {
    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let public = TransactionLogDetails::Public(logs.clone());
    let private = TransactionLogDetails::Private(logs.commitment());
    assert_eq!(public.to_elements(), Some(logs.to_elements()));
    assert_eq!(private.to_elements(), None);
    assert_eq!(public.commitment(), private.commitment());
}

#[rstest]
#[case::empty(vec![])]
#[case::with_logs(vec![TransactionLog::mock(1)])]
fn log_visibility_follows_the_native_account(#[case] entries: Vec<TransactionLog>) {
    let private_account = ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap();
    let public_account = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap();
    let public = TransactionLogDetails::Public(TransactionLogs::new(entries).unwrap());
    let private = TransactionLogDetails::Private(Word::empty());
    assert!(public.validate_visibility(public_account).is_ok());
    assert!(private.validate_visibility(private_account).is_ok());
    assert_matches!(
        public.validate_visibility(private_account),
        Err(TransactionLogError::VisibilityMismatch)
    );
    assert_matches!(
        private.validate_visibility(public_account),
        Err(TransactionLogError::VisibilityMismatch)
    );
}
