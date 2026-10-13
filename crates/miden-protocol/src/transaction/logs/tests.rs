use assert_matches::assert_matches;
use miden_assembly::Assembler;
use miden_processor::{DefaultHost, FastProcessor, StackInputs};
use rstest::rstest;

use super::*;
use crate::account::{AccountIdV1, AccountIdVersion, AccountType};
use crate::utils::hex_to_bytes;
use crate::utils::serde::SliceReader;

/// Builds fixture account IDs with an explicit account type and suffix.
fn emitter(suffix: u32, account_type: AccountType) -> AccountId {
    let prefix = (AccountIdVersion::Version1 as u32)
        | ((account_type.as_u8() as u32) << AccountIdV1::ACCOUNT_TYPE_SHIFT);
    AccountId::try_from_elements(Felt::from(suffix), Felt::from(prefix)).unwrap()
}

/// Builds a topic with explicit elements for commitment and serialization vectors.
fn topic(a: u32, b: u32) -> LogTopic {
    LogTopic::new([Felt::from(a), Felt::from(b)])
}

/// Builds a transaction log with a fixed emitter and topic, repeating one content word.
fn log(num_words: usize) -> TransactionLog {
    TransactionLog::new(
        emitter(256, AccountType::Private),
        topic(1, 2),
        vec![Word::from([9u32, 10, 11, 12]); num_words],
    )
    .unwrap()
}

/// Fixed private/public emitters, odd/even content lengths, and a duplicate transaction log with an
/// empty content.
fn vector_logs() -> Vec<TransactionLog> {
    vec![
        log(0),
        TransactionLog::new(
            emitter(512, AccountType::Public),
            topic(5, 6),
            vec![Word::from([9u32, 10, 11, 12])],
        )
        .unwrap(),
        TransactionLog::new(
            emitter(256, AccountType::Private),
            topic(1, 2),
            vec![Word::from([1u32, 2, 3, 4]), Word::empty()],
        )
        .unwrap(),
        log(0),
    ]
}

#[test]
fn empty_collection() {
    let logs = TransactionLogs::default();
    assert_eq!(logs, TransactionLogs::new(vec![]).unwrap());
    assert!(logs.is_empty());
    assert_eq!(logs.num_logs(), 0);
    assert_eq!(logs.num_content_words(), 0);
    assert_eq!(logs.commitment(), Word::empty());
    assert_eq!(logs.to_bytes(), [0, 0]);
    assert_eq!(logs.get_size_hint(), 2);
    assert_eq!(TransactionLogs::read_from_bytes(&[0, 0]).unwrap(), logs);
}

#[test]
fn empty_content_is_not_an_absent_log_or_zero_word_content() {
    let empty_content = log(0);
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

#[rstest]
#[case::emitter_suffix(|logs: &mut Vec<TransactionLog>| logs[1].emitter = emitter(768, AccountType::Public))]
#[case::emitter_prefix(|logs: &mut Vec<TransactionLog>| logs[1].emitter = emitter(512, AccountType::Private))]
#[case::topic_suffix(|logs: &mut Vec<TransactionLog>| logs[1].topic = topic(0, 6))]
#[case::topic_prefix(|logs: &mut Vec<TransactionLog>| logs[1].topic = topic(5, 0))]
#[case::content_contents(|logs: &mut Vec<TransactionLog>| logs[1].content[0] = Word::empty())]
#[case::content_length(|logs: &mut Vec<TransactionLog>| logs[1].content.push(Word::empty()))]
#[case::order(|logs: &mut Vec<TransactionLog>| logs.swap(0, 1))]
#[case::removed_log(|logs: &mut Vec<TransactionLog>| logs.truncate(3))]
#[case::added_log(|logs: &mut Vec<TransactionLog>| logs.push(log(0)))]
fn commitment_binds_every_field_count_and_order(#[case] mutate: fn(&mut Vec<TransactionLog>)) {
    let entries = vector_logs();
    let commitment = TransactionLogs::new(entries.clone()).unwrap().commitment();
    let mut changed = entries;
    mutate(&mut changed);
    assert_ne!(commitment, TransactionLogs::new(changed).unwrap().commitment());
}

#[rstest]
#[case::empty(0)]
#[case::maximum(TransactionLog::MAX_NUM_WORDS)]
fn log_serialization(#[case] num_words: usize) {
    let entry = log(num_words);
    let bytes = entry.to_bytes();
    assert_eq!(entry.get_size_hint(), bytes.len());
    assert_eq!(TransactionLog::read_from_bytes(&bytes).unwrap(), entry);
    assert_eq!(entry.content().len(), num_words);
}

#[test]
fn maximum_collection_serialization() {
    let full_contents = TransactionLogs::MAX_NUM_WORDS / TransactionLog::MAX_NUM_WORDS;
    let mut entries = vec![log(TransactionLog::MAX_NUM_WORDS); full_contents];
    entries.resize(TransactionLogs::MAX_COUNT, log(0));
    let logs = TransactionLogs::new(entries).unwrap();
    assert_eq!(logs.num_logs(), TransactionLogs::MAX_COUNT);
    assert_eq!(logs.num_content_words(), TransactionLogs::MAX_NUM_WORDS);
    let bytes = logs.to_bytes();
    assert_eq!(logs.get_size_hint(), bytes.len());
    assert_eq!(TransactionLogs::read_from_bytes(&bytes).unwrap(), logs);
}

#[test]
fn constructors_reject_excessive_sizes() {
    assert_matches!(
        TransactionLog::new(
            emitter(256, AccountType::Private),
            topic(0, 0),
            vec![Word::empty(); TransactionLog::MAX_NUM_WORDS + 1],
        )
        .unwrap_err(),
        TransactionLogError::TooManyContentWords(count) if count == TransactionLog::MAX_NUM_WORDS + 1
    );
    assert_matches!(
        TransactionLogs::new(vec![log(0); TransactionLogs::MAX_COUNT + 1]).unwrap_err(),
        TransactionLogError::TooManyLogs(count) if count == TransactionLogs::MAX_COUNT + 1
    );

    let mut entries = vec![
        log(TransactionLog::MAX_NUM_WORDS);
        TransactionLogs::MAX_NUM_WORDS / TransactionLog::MAX_NUM_WORDS
    ];
    entries.push(log(1));
    assert_matches!(
        TransactionLogs::new(entries).unwrap_err(),
        TransactionLogError::TooManyTotalContentWords(count) if count == TransactionLogs::MAX_NUM_WORDS + 1
    );
}

fn assert_invalid_value(error: DeserializationError, expected: TransactionLogError) {
    assert_matches!(error, DeserializationError::InvalidValue(message) => {
        assert_eq!(message, expected.to_string());
    });
}

#[test]
fn decoder_rejects_log_count_before_reading_transaction_logs() {
    let mut bytes = Vec::new();
    bytes.write_u16((TransactionLogs::MAX_COUNT + 1) as u16);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    assert_invalid_value(
        TransactionLogs::read_from(&mut reader).unwrap_err(),
        TransactionLogError::TooManyLogs(TransactionLogs::MAX_COUNT + 1),
    );
    assert_eq!(reader.read_u8().unwrap(), 0xab);
}

#[rstest]
#[case::standalone(false)]
#[case::collection(true)]
fn decoder_rejects_content_length_before_reading_content(#[case] collection: bool) {
    let mut bytes = Vec::new();
    if collection {
        bytes.write_u16(1);
    }
    bytes.write(emitter(256, AccountType::Private));
    bytes.write(topic(0, 0));
    bytes.write_u16((TransactionLog::MAX_NUM_WORDS + 1) as u16);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    let error = if collection {
        TransactionLogs::read_from(&mut reader).unwrap_err()
    } else {
        TransactionLog::read_from(&mut reader).unwrap_err()
    };
    assert_invalid_value(
        error,
        TransactionLogError::TooManyContentWords(TransactionLog::MAX_NUM_WORDS + 1),
    );
    assert_eq!(reader.read_u8().unwrap(), 0xab);
}

#[test]
fn decoder_rejects_total_length_before_reading_excess_content() {
    let full_contents = TransactionLogs::MAX_NUM_WORDS / TransactionLog::MAX_NUM_WORDS;
    let mut bytes = Vec::new();
    bytes.write_u16((full_contents + 1) as u16);
    for _ in 0..full_contents {
        bytes.write(log(TransactionLog::MAX_NUM_WORDS));
    }
    bytes.write(emitter(256, AccountType::Private));
    bytes.write(topic(0, 0));
    bytes.write_u16(1);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    assert_invalid_value(
        TransactionLogs::read_from(&mut reader).unwrap_err(),
        TransactionLogError::TooManyTotalContentWords(TransactionLogs::MAX_NUM_WORDS + 1),
    );
    assert_eq!(reader.read_u8().unwrap(), 0xab);
}

#[test]
fn decoder_rejects_invalid_account_id() {
    let mut bytes = log(0).to_bytes();
    bytes[..AccountId::SERIALIZED_SIZE].fill(0);
    assert_matches!(
        TransactionLog::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(_))
    );
}

#[rstest]
#[case::topic(AccountId::SERIALIZED_SIZE)]
#[case::content(TransactionLog::min_serialized_size())]
fn decoder_rejects_noncanonical_field_elements(#[case] offset: usize) {
    let mut bytes = log(1).to_bytes();
    bytes[offset..offset + 8].copy_from_slice(&Felt::ORDER.to_le_bytes());
    assert_matches!(
        TransactionLog::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(_))
    );
}

#[test]
fn decoder_rejects_truncated_transaction_logs_and_collections() {
    let bytes = log(2).to_bytes();
    for len in 0..bytes.len() {
        assert!(TransactionLog::read_from_bytes(&bytes[..len]).is_err(), "length {len}");
    }
    let bytes = TransactionLogs::new(vector_logs()).unwrap().to_bytes();
    for len in 0..bytes.len() {
        assert!(TransactionLogs::read_from_bytes(&bytes[..len]).is_err(), "length {len}");
    }
}

#[test]
fn named_topic_matches_masm_word_slice() {
    let [first, second] =
        LogTopic::from_name("miden::standards::access::rbac::role_granted").as_elements();
    let source = format!(
        r#"
        const ROLE_GRANTED = word("miden::standards::access::rbac::role_granted")
        begin
            push.ROLE_GRANTED[0..2]
            push.{first} assert_eq
            push.{second} assert_eq
        end
    "#
    );
    let program = Assembler::default()
        .assemble_program("log-topic", source)
        .unwrap()
        .unwrap_program();
    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut DefaultHost::default())
        .unwrap();
}

#[test]
fn topics_serialize_as_two_canonical_felts() {
    let value = topic(1, 2);
    let bytes = hex_to_bytes::<16>("0x01000000000000000200000000000000").unwrap();
    assert_eq!(value.to_bytes(), bytes);
    assert_eq!(LogTopic::read_from_bytes(&bytes).unwrap(), value);
    assert_eq!(value.get_size_hint(), 16);
    for offset in [0, 8] {
        let mut invalid = bytes;
        invalid[offset..offset + 8].copy_from_slice(&Felt::ORDER.to_le_bytes());
        assert!(LogTopic::read_from_bytes(&invalid).is_err());
    }
}

#[test]
fn submitted_data_serializes_public_transaction_logs_or_only_a_private_commitment() {
    let logs = TransactionLogs::new(vector_logs()).unwrap();
    let public = TransactionLogDetails::Public(logs.clone());
    let mut public_bytes = vec![AccountType::Public.as_u8()];
    public_bytes.extend(logs.to_bytes());
    assert_eq!(public.to_bytes(), public_bytes);
    assert_eq!(public.to_commitment(), logs.commitment());
    assert_eq!(public.to_elements(), Some(logs.to_elements()));

    // Private data stores the supplied commitment without deriving it.
    let commitment = Word::from([11u32, 22, 33, 44]);
    let private = TransactionLogDetails::Private(commitment);
    let mut private_bytes = vec![AccountType::Private.as_u8()];
    private_bytes.extend(commitment.to_bytes());
    assert_eq!(private.to_bytes(), private_bytes);
    assert_eq!(private.get_size_hint(), 33);
    assert_eq!(private.to_commitment(), commitment);
    assert_eq!(private.to_elements(), None);

    for data in [public, private] {
        let bytes = data.to_bytes();
        assert_eq!(data.get_size_hint(), bytes.len());
        assert_eq!(TransactionLogDetails::read_from_bytes(&bytes).unwrap(), data);
        for len in 0..bytes.len() {
            assert!(TransactionLogDetails::read_from_bytes(&bytes[..len]).is_err());
        }
    }
    assert!(TransactionLogDetails::read_from_bytes(&[2]).is_err());
}

#[rstest]
#[case::empty(vec![])]
#[case::with_foreign_emitters(vector_logs())]
fn log_visibility_follows_the_native_account(#[case] entries: Vec<TransactionLog>) {
    let private_account = emitter(256, AccountType::Private);
    let public_account = emitter(512, AccountType::Public);
    assert!(!private_account.is_public());
    assert!(public_account.is_public());
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

#[test]
fn public_submission_decoder_preserves_collection_bounds() {
    let mut bytes = vec![AccountType::Public.as_u8()];
    bytes.write_u16((TransactionLogs::MAX_COUNT + 1) as u16);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    assert_invalid_value(
        TransactionLogDetails::read_from(&mut reader).unwrap_err(),
        TransactionLogError::TooManyLogs(TransactionLogs::MAX_COUNT + 1),
    );
    assert_eq!(reader.read_u8().unwrap(), 0xab);
}
