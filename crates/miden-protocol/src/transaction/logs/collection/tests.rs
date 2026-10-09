use alloc::string::ToString;
use alloc::vec::Vec;

use rstest::rstest;

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
    TransactionLogData,
    TransactionLogDataCollection,
    TransactionLogError,
    TransactionLogs,
};
use crate::utils::serde::{ByteWriter, Deserializable, DeserializationError, Serializable};
use crate::{
    MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
    MAX_LOG_PAYLOAD_WORDS,
    MAX_LOG_PAYLOAD_WORDS_PER_TX,
    MAX_LOGS_PER_TX,
    MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
    MAX_PUBLIC_LOGS_PER_BLOCK,
    Word,
};

fn public_log(words: usize) -> TransactionLog {
    TransactionLog::new(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
        LogTopic::from_name("test::updated"),
        vec![Word::from([17u32; 4]); words],
    )
    .unwrap()
}

fn header(account: AccountId, data: &TransactionLogData, state: u32) -> TransactionHeader {
    TransactionHeader::new(
        account,
        Word::from([state; 4]),
        Word::from([state + 1; 4]),
        InputNotes::default(),
        vec![],
        data.commitment(),
    )
    .unwrap()
}

#[test]
fn block_transaction_logs_roundtrip_and_validate_associations() {
    let public = TransactionLogData::Public(
        TransactionLogs::new(vec![public_log(1), public_log(1)]).unwrap(),
    );
    let private = TransactionLogData::Private(Word::from([73u32; 4]));
    let headers = OrderedTransactionHeaders::new_unchecked(vec![
        header(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(), &public, 1),
        header(ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(), &private, 3),
    ]);
    let data = TransactionLogDataCollection::new(vec![public.clone(), private.clone()]).unwrap();
    let block = BlockBody::new(vec![], vec![], vec![], data.clone(), headers.clone()).unwrap();
    assert_eq!(BlockBody::read_from_bytes(&block.to_bytes()).unwrap(), block);
    for entries in [
        vec![],
        vec![public.clone()],
        vec![public.clone(), private.clone(), private.clone()],
    ] {
        let invalid = TransactionLogDataCollection::new(entries).unwrap();
        assert!(matches!(
            BlockBody::new(vec![], vec![], vec![], invalid, headers.clone()),
            Err(BlockBodyError::LogData(TransactionLogError::AssociationCount))
        ));
    }
    let reversed = TransactionLogDataCollection::new(vec![private, public]).unwrap();
    assert_eq!(
        reversed.validate_for_block(&headers),
        Err(TransactionLogError::VisibilityMismatch)
    );

    let changed = TransactionLogDataCollection::new(vec![
        TransactionLogData::Public(TransactionLogs::new(vec![public_log(2)]).unwrap()),
        data.as_slice()[1].clone(),
    ])
    .unwrap();
    assert_eq!(
        changed.validate_for_block(&headers),
        Err(TransactionLogError::CommitmentMismatch(0))
    );
    let duplicate_headers =
        OrderedTransactionHeaders::new_unchecked(vec![headers.as_slice()[0].clone(); 2]);
    let duplicate_data =
        TransactionLogDataCollection::new(vec![data.as_slice()[0].clone(); 2]).unwrap();
    assert!(BlockBody::new(vec![], vec![], vec![], duplicate_data, duplicate_headers).is_err());
}

#[rstest]
#[case::batch(LogDataScope::Batch)]
#[case::block(LogDataScope::Block)]
fn payload_word_limit_accepts_the_boundary_and_rejects_one_more(#[case] scope: LogDataScope) {
    let entry = TransactionLogData::Public(
        TransactionLogs::new(vec![
            public_log(MAX_LOG_PAYLOAD_WORDS);
            MAX_LOG_PAYLOAD_WORDS_PER_TX / MAX_LOG_PAYLOAD_WORDS
        ])
        .unwrap(),
    );
    let extra = TransactionLogData::Public(TransactionLogs::new(vec![public_log(1)]).unwrap());
    let count = scope.budget().payload_words / MAX_LOG_PAYLOAD_WORDS_PER_TX;
    assert_aggregate_limit(scope, entry, count, extra);
}

#[rstest]
#[case::batch(LogDataScope::Batch)]
#[case::block(LogDataScope::Block)]
fn public_transaction_log_limit_accepts_the_boundary_and_rejects_one_more(
    #[case] scope: LogDataScope,
) {
    let entry = TransactionLogData::Public(
        TransactionLogs::new(vec![public_log(0); MAX_LOGS_PER_TX]).unwrap(),
    );
    let extra = TransactionLogData::Public(TransactionLogs::new(vec![public_log(0)]).unwrap());
    let count = scope.budget().public_logs / MAX_LOGS_PER_TX;
    assert_aggregate_limit(scope, entry, count, extra);
}

#[rstest]
#[case::batch_public(LogDataScope::Batch, TransactionLogData::Public(TransactionLogs::default()))]
#[case::batch_private(LogDataScope::Batch, TransactionLogData::Private(Word::empty()))]
#[case::block_public(LogDataScope::Block, TransactionLogData::Public(TransactionLogs::default()))]
#[case::block_private(LogDataScope::Block, TransactionLogData::Private(Word::empty()))]
fn transaction_entry_limit_includes_empty_and_private_entries(
    #[case] scope: LogDataScope,
    #[case] entry: TransactionLogData,
) {
    assert_aggregate_limit(scope, entry.clone(), scope.budget().entries, entry);
}

fn assert_aggregate_limit(
    scope: LogDataScope,
    entry: TransactionLogData,
    count: usize,
    extra: TransactionLogData,
) {
    let mut entries = vec![entry; count];
    assert!(TransactionLogDataCollection::validate_budget(entries.iter(), scope).is_ok());
    let data = TransactionLogDataCollection::new(entries.clone()).unwrap();
    let encoded = data.to_bytes();
    assert_eq!(encoded.len(), data.get_size_hint());
    assert_eq!(TransactionLogDataCollection::read_from_bytes(&encoded).unwrap(), data);

    entries.push(extra);
    assert_eq!(
        TransactionLogDataCollection::validate_budget(entries.iter(), scope),
        Err(TransactionLogError::AggregateBudget)
    );
}

#[test]
fn decoder_stops_when_public_resources_are_exhausted() {
    for (entry, count) in [
        (
            TransactionLogData::Public(
                TransactionLogs::new(vec![public_log(0); MAX_LOGS_PER_TX]).unwrap(),
            ),
            MAX_PUBLIC_LOGS_PER_BLOCK / MAX_LOGS_PER_TX,
        ),
        (
            TransactionLogData::Public(
                TransactionLogs::new(vec![public_log(MAX_LOG_PAYLOAD_WORDS); 2]).unwrap(),
            ),
            MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK / MAX_LOG_PAYLOAD_WORDS_PER_TX,
        ),
    ] {
        let mut bytes = Vec::new();
        bytes.write_u32(count as u32 + 2);
        for _ in 0..=count {
            bytes.write_u32(entry.get_size_hint() as u32);
            entry.write_into(&mut bytes);
        }
        // The next frame is absent. Reject the exhausted budget before trying to read it.
        assert_eq!(
            TransactionLogDataCollection::read_from_bytes(&bytes),
            Err(DeserializationError::InvalidValue(
                TransactionLogError::AggregateBudget.to_string()
            ))
        );
    }
}

#[test]
fn decoder_rejects_oversized_counts_and_lengths_before_reading_payloads() {
    let mut bytes = Vec::new();
    bytes.write_u32(MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK as u32 + 1);
    assert!(matches!(
        TransactionLogDataCollection::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(_))
    ));
    bytes.clear();
    bytes.write_u32(1);
    bytes.write_u32(u32::MAX);
    assert!(matches!(
        TransactionLogDataCollection::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(_))
    ));
}

#[test]
fn decoder_rejects_trailing_bytes_in_a_transaction_frame() {
    let entry = TransactionLogData::Private(Word::empty());
    let mut bytes = Vec::new();
    bytes.write_u32(1);
    bytes.write_u32(entry.get_size_hint() as u32 + 1);
    entry.write_into(&mut bytes);
    bytes.push(0);
    assert!(matches!(
        TransactionLogDataCollection::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(_))
    ));
}

#[test]
fn decoder_accepts_the_largest_transaction_frame_and_rejects_one_byte_more() {
    let mut remaining_words = MAX_LOG_PAYLOAD_WORDS_PER_TX;
    let logs = (0..MAX_LOGS_PER_TX)
        .map(|_| {
            let words = remaining_words.min(MAX_LOG_PAYLOAD_WORDS);
            remaining_words -= words;
            public_log(words)
        })
        .collect();
    assert_eq!(remaining_words, 0);
    let entry = TransactionLogData::Public(TransactionLogs::new(logs).unwrap());
    let frame_size = entry.to_bytes().len();
    let data = TransactionLogDataCollection::new(vec![entry]).unwrap();
    assert_eq!(TransactionLogDataCollection::read_from_bytes(&data.to_bytes()).unwrap(), data);

    // Omit the payload: the size must be rejected before the decoder tries to read it.
    let mut bytes = Vec::new();
    bytes.write_u32(1);
    bytes.write_u32(frame_size as u32 + 1);
    assert_eq!(
        TransactionLogDataCollection::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(
            "transaction log data frame exceeds transaction limit".into()
        ))
    );
}
