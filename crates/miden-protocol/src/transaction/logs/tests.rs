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

/// Builds a transaction log with a fixed emitter and topic, repeating one payload word.
fn log(num_words: usize) -> TransactionLog {
    TransactionLog::new(
        emitter(256, AccountType::Private),
        topic(1, 2),
        vec![Word::from([9u32, 10, 11, 12]); num_words],
    )
    .unwrap()
}

/// Fixed private/public emitters, odd/even payload lengths, and a duplicate transaction log with an
/// empty payload.
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
    assert_eq!(logs.num_payload_words(), 0);
    assert_eq!(logs.commitment(), Word::empty());
    assert_eq!(logs.to_bytes(), [0, 0]);
    assert_eq!(logs.get_size_hint(), 2);
    assert_eq!(TransactionLogs::read_from_bytes(&[0, 0]).unwrap(), logs);
}

#[test]
fn empty_payload_is_not_an_absent_log_or_zero_word_payload() {
    let empty_payload = log(0);
    assert_eq!(empty_payload.payload_commitment(), Word::empty());

    let mut zero_word_payload = empty_payload.clone();
    zero_word_payload.payload.push(Word::empty());
    assert_ne!(zero_word_payload.payload_commitment(), Word::empty());

    let logs = TransactionLogs::new(vec![empty_payload]).unwrap();
    assert!(!logs.is_empty());
    assert_ne!(logs.commitment(), Word::empty());
    assert_ne!(
        logs.commitment(),
        TransactionLogs::new(vec![zero_word_payload]).unwrap().commitment()
    );
}

#[test]
fn commitment_vectors() {
    let payload_commitments = [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x63889211f82b96d496810b890af36603e52d416bc913f16dfb85c2a453295c2d",
        "0xdb365b9fbe32a920a0b7396c0ba5d09fce08362e113affe99cdc51e55e6291b5",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ];
    // Individual commitments are also checked against a direct permutation below.
    let individual_commitments = [
        "0x17203a1b029a5d2cfe4d94ec68da2a204d2cdb7ad60c7f8cc5c3eded29c94810",
        "0x97da466301344a0647316ec6df65a06dc9953150f2e8f9117329974810462eae",
        "0xb0d045543e0ff96da679f79428e26b641bfc3578a31b8ad221c09ef9508bf345",
        "0x17203a1b029a5d2cfe4d94ec68da2a204d2cdb7ad60c7f8cc5c3eded29c94810",
    ];
    // Pin one through four transaction logs: half, full, full plus half, and two full hash rates.
    // The fourth entry duplicates the first, so these also pin transaction log multiplicity.
    let collection_commitments = [
        "0xbf0d38cfceaa53cebbc701dec388d0be838452add786b934c26789273748d2ad",
        "0xad7e7b073214899b118bf50ee4f4d9ff4bd92624f1d70e594b570f64cf369981",
        "0x23d2173c6dee33b73935164fc32ede1c3e06ecfb09a4a5efd6be6c6e7fd85dd7",
        "0x245f9c8952bd6b2d27f35815104353866243cbb5c92af0847e4afb9c0d654f85",
    ];
    let mut logs = TransactionLogs::default();
    for (index, entry) in vector_logs().into_iter().enumerate() {
        assert_eq!(entry.payload_commitment(), Word::try_from(payload_commitments[index]).unwrap());
        assert_eq!(entry.commitment(), Word::try_from(individual_commitments[index]).unwrap());
        logs.try_push(entry).unwrap();
        assert_eq!(logs.commitment(), Word::try_from(collection_commitments[index]).unwrap());
    }
}

#[rstest]
#[case::emitter_suffix(|logs: &mut Vec<TransactionLog>| logs[1].emitter = emitter(768, AccountType::Public))]
#[case::emitter_prefix(|logs: &mut Vec<TransactionLog>| logs[1].emitter = emitter(512, AccountType::Private))]
#[case::topic_0(|logs: &mut Vec<TransactionLog>| logs[1].topic = topic(0, 6))]
#[case::topic_1(|logs: &mut Vec<TransactionLog>| logs[1].topic = topic(5, 0))]
#[case::payload_contents(|logs: &mut Vec<TransactionLog>| logs[1].payload[0] = Word::empty())]
#[case::payload_length(|logs: &mut Vec<TransactionLog>| logs[1].payload.push(Word::empty()))]
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

/// Pins the individual transaction log's metadata order and domain independently of
/// `merge_in_domain`.
#[test]
fn individual_commitments_match_permutation_layout() {
    for log in vector_logs() {
        let [topic_0, topic_1] = log.topic().as_elements();
        let metadata = [log.emitter().suffix(), log.emitter().prefix().as_felt(), topic_0, topic_1];
        let mut state = [Felt::ZERO; Hasher::STATE_WIDTH];
        // Pin the specified domain rather than reading the implementation's constant.
        state[Hasher::CAPACITY_RANGE.start + 1] = Felt::from(0x02_0005u32);
        // The rate contains the metadata word followed by the payload commitment.
        state[..4].copy_from_slice(&metadata);
        state[4..8].copy_from_slice(log.payload_commitment().as_elements());
        Hasher::apply_permutation(&mut state);
        assert_eq!(log.commitment().as_elements(), &state[Hasher::DIGEST_RANGE]);
    }
}

#[test]
fn serialization_vector() {
    let bytes = hex_to_bytes::<230>(concat!(
        "0x0400",
        "000000000000000100000000000001",
        "01000000000000000200000000000000",
        "0000",
        "000000000000001100000000000002",
        "05000000000000000600000000000000",
        "0100",
        "09000000000000000a000000000000000b000000000000000c00000000000000",
        "000000000000000100000000000001",
        "01000000000000000200000000000000",
        "0200",
        "0100000000000000020000000000000003000000000000000400000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000100000000000001",
        "01000000000000000200000000000000",
        "0000",
    ))
    .unwrap();

    let logs = TransactionLogs::new(vector_logs()).unwrap();
    assert_eq!(logs.to_bytes(), bytes);
    assert_eq!(logs.get_size_hint(), bytes.len());
    assert_eq!(TransactionLogs::read_from_bytes(&bytes).unwrap(), logs);
    assert_eq!(TransactionLog::min_serialized_size(), 33);
    assert_eq!(TransactionLogs::min_serialized_size(), 2);
}

#[rstest]
#[case::empty(0)]
#[case::maximum(MAX_LOG_PAYLOAD_WORDS)]
fn log_serialization(#[case] num_words: usize) {
    let entry = log(num_words);
    let bytes = entry.to_bytes();
    assert_eq!(entry.get_size_hint(), bytes.len());
    assert_eq!(TransactionLog::read_from_bytes(&bytes).unwrap(), entry);
    assert_eq!(entry.payload().len(), num_words);
}

#[test]
fn maximum_collection_serialization() {
    let full_payloads = MAX_LOG_PAYLOAD_WORDS_PER_TX / MAX_LOG_PAYLOAD_WORDS;
    let mut entries = vec![log(MAX_LOG_PAYLOAD_WORDS); full_payloads];
    entries.resize(MAX_LOGS_PER_TX, log(0));
    let logs = TransactionLogs::new(entries).unwrap();
    assert_eq!(logs.num_logs(), MAX_LOGS_PER_TX);
    assert_eq!(logs.num_payload_words(), MAX_LOG_PAYLOAD_WORDS_PER_TX);
    let bytes = logs.to_bytes();
    assert_eq!(logs.get_size_hint(), bytes.len());
    assert_eq!(TransactionLogs::read_from_bytes(&bytes).unwrap(), logs);
}

#[test]
fn constructors_reject_excessive_sizes() {
    assert_eq!(
        TransactionLog::new(
            emitter(256, AccountType::Private),
            topic(0, 0),
            vec![Word::empty(); MAX_LOG_PAYLOAD_WORDS + 1],
        )
        .unwrap_err(),
        TransactionLogError::TooManyPayloadWords(MAX_LOG_PAYLOAD_WORDS + 1)
    );
    assert_eq!(
        TransactionLogs::new(vec![log(0); MAX_LOGS_PER_TX + 1]).unwrap_err(),
        TransactionLogError::TooManyLogs(MAX_LOGS_PER_TX + 1)
    );

    let mut entries =
        vec![log(MAX_LOG_PAYLOAD_WORDS); MAX_LOG_PAYLOAD_WORDS_PER_TX / MAX_LOG_PAYLOAD_WORDS];
    entries.push(log(1));
    assert_eq!(
        TransactionLogs::new(entries).unwrap_err(),
        TransactionLogError::TooManyTotalPayloadWords(MAX_LOG_PAYLOAD_WORDS_PER_TX + 1)
    );
}

#[test]
fn failed_appends_leave_the_collection_unchanged() {
    let mut logs = TransactionLogs::new(vec![log(0); MAX_LOGS_PER_TX]).unwrap();
    let cached = logs.commitment();
    let before = logs.clone();
    assert_eq!(
        logs.try_push(log(0)).unwrap_err(),
        TransactionLogError::TooManyLogs(MAX_LOGS_PER_TX + 1)
    );
    assert_eq!(logs, before);
    assert_eq!(logs.commitment.get(), Some(&cached));
    assert_eq!(logs.log_commitments, before.log_commitments);

    let mut logs = TransactionLogs::new(vec![
        log(MAX_LOG_PAYLOAD_WORDS);
        MAX_LOG_PAYLOAD_WORDS_PER_TX / MAX_LOG_PAYLOAD_WORDS
    ])
    .unwrap();
    let cached = logs.commitment();
    let before = logs.clone();
    assert_eq!(
        logs.try_push(log(1)).unwrap_err(),
        TransactionLogError::TooManyTotalPayloadWords(MAX_LOG_PAYLOAD_WORDS_PER_TX + 1)
    );
    assert_eq!(logs, before);
    assert_eq!(logs.commitment.get(), Some(&cached));
    assert_eq!(logs.log_commitments, before.log_commitments);
    logs.try_push(log(0)).unwrap();
}

fn assert_invalid_value(error: DeserializationError, expected: TransactionLogError) {
    assert_matches!(error, DeserializationError::InvalidValue(message) => {
        assert_eq!(message, expected.to_string());
    });
}

#[test]
fn decoder_rejects_log_count_before_reading_transaction_logs() {
    let mut bytes = Vec::new();
    bytes.write_u16((MAX_LOGS_PER_TX + 1) as u16);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    assert_invalid_value(
        TransactionLogs::read_from(&mut reader).unwrap_err(),
        TransactionLogError::TooManyLogs(MAX_LOGS_PER_TX + 1),
    );
    assert_eq!(reader.read_u8().unwrap(), 0xab);
}

#[rstest]
#[case::standalone(false)]
#[case::collection(true)]
fn decoder_rejects_payload_length_before_reading_payload(#[case] collection: bool) {
    let mut bytes = Vec::new();
    if collection {
        bytes.write_u16(1);
    }
    bytes.write(emitter(256, AccountType::Private));
    bytes.write(topic(0, 0));
    bytes.write_u16((MAX_LOG_PAYLOAD_WORDS + 1) as u16);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    let error = if collection {
        TransactionLogs::read_from(&mut reader).unwrap_err()
    } else {
        TransactionLog::read_from(&mut reader).unwrap_err()
    };
    assert_invalid_value(
        error,
        TransactionLogError::TooManyPayloadWords(MAX_LOG_PAYLOAD_WORDS + 1),
    );
    assert_eq!(reader.read_u8().unwrap(), 0xab);
}

#[test]
fn decoder_rejects_total_length_before_reading_excess_payload() {
    let full_payloads = MAX_LOG_PAYLOAD_WORDS_PER_TX / MAX_LOG_PAYLOAD_WORDS;
    let mut bytes = Vec::new();
    bytes.write_u16((full_payloads + 1) as u16);
    for _ in 0..full_payloads {
        bytes.write(log(MAX_LOG_PAYLOAD_WORDS));
    }
    bytes.write(emitter(256, AccountType::Private));
    bytes.write(topic(0, 0));
    bytes.write_u16(1);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    assert_invalid_value(
        TransactionLogs::read_from(&mut reader).unwrap_err(),
        TransactionLogError::TooManyTotalPayloadWords(MAX_LOG_PAYLOAD_WORDS_PER_TX + 1),
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
#[case::payload(TransactionLog::min_serialized_size())]
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
fn collection_cache_is_lazy_and_invalidated_by_appends() {
    let mut logs = TransactionLogs::new(vector_logs()).unwrap();
    assert!(logs.commitment.get().is_none());
    let uncached = logs.clone();
    let commitment = logs.commitment();
    assert_eq!(logs.commitment.get(), Some(&commitment));
    assert_eq!(logs.commitment(), commitment);
    assert_eq!(logs, uncached);
    assert_eq!(logs.to_bytes(), uncached.to_bytes());
    assert_eq!(logs.clone().commitment.get(), Some(&commitment));
    let decoded = TransactionLogs::read_from_bytes(&logs.to_bytes()).unwrap();
    assert!(decoded.commitment.get().is_none());
    assert_eq!(decoded, logs);
    assert_eq!(decoded.commitment(), commitment);

    logs.try_push(log(0)).unwrap();
    assert!(logs.commitment.get().is_none());
    assert_ne!(logs.commitment(), commitment);
    assert_eq!(
        logs.commitment(),
        TransactionLogs::new(logs.clone().into_vec()).unwrap().commitment()
    );
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
    let public = TransactionLogData::Public(logs.clone());
    let mut public_bytes = vec![0];
    public_bytes.extend(logs.to_bytes());
    assert_eq!(public.to_bytes(), public_bytes);
    assert_eq!(public.commitment(), logs.commitment());

    // Private data stores the supplied commitment without deriving it.
    let commitment = Word::from([11u32, 22, 33, 44]);
    let private = TransactionLogData::Private(commitment);
    let mut private_bytes = vec![1];
    private_bytes.extend(commitment.to_bytes());
    assert_eq!(private.to_bytes(), private_bytes);
    assert_eq!(private.get_size_hint(), 33);
    assert_eq!(private.commitment(), commitment);

    for data in [public, private] {
        let bytes = data.to_bytes();
        assert_eq!(data.get_size_hint(), bytes.len());
        assert_eq!(TransactionLogData::read_from_bytes(&bytes).unwrap(), data);
        for len in 0..bytes.len() {
            assert!(TransactionLogData::read_from_bytes(&bytes[..len]).is_err());
        }
    }
    assert!(TransactionLogData::read_from_bytes(&[2]).is_err());
}

#[rstest]
#[case::empty(vec![])]
#[case::with_foreign_emitters(vector_logs())]
fn log_visibility_follows_the_native_account(#[case] entries: Vec<TransactionLog>) {
    let private_account = emitter(256, AccountType::Private);
    let public_account = emitter(512, AccountType::Public);
    assert!(!private_account.is_public());
    assert!(public_account.is_public());
    let public = TransactionLogData::Public(TransactionLogs::new(entries).unwrap());
    let private = TransactionLogData::Private(Word::empty());
    assert_eq!(public.validate_visibility(public_account), Ok(()));
    assert_eq!(private.validate_visibility(private_account), Ok(()));
    assert_eq!(
        public.validate_visibility(private_account),
        Err(TransactionLogError::VisibilityMismatch)
    );
    assert_eq!(
        private.validate_visibility(public_account),
        Err(TransactionLogError::VisibilityMismatch)
    );
}

#[test]
fn public_submission_decoder_preserves_collection_bounds() {
    let mut bytes = vec![0];
    bytes.write_u16((MAX_LOGS_PER_TX + 1) as u16);
    bytes.write_u8(0xab);
    let mut reader = SliceReader::new(&bytes);
    assert_invalid_value(
        TransactionLogData::read_from(&mut reader).unwrap_err(),
        TransactionLogError::TooManyLogs(MAX_LOGS_PER_TX + 1),
    );
    assert_eq!(reader.read_u8().unwrap(), 0xab);
}

#[test]
fn logs_remain_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TransactionLogs>();
    assert_send_sync::<TransactionLogData>();
}

#[test]
fn private_transaction_logs_require_a_nonzero_salt_and_commit_to_it() {
    let private_account = emitter(256, AccountType::Private);
    let public_account = emitter(512, AccountType::Public);
    let logs = TransactionLogs::new(vec![log(1)]).unwrap();
    let salt = Word::from([17u32, 29, 31, 43]);
    let other_salt = Word::from([47u32, 53, 59, 61]);

    assert_eq!(
        logs.commitment_for_account(private_account, Word::empty()),
        Err(TransactionLogError::MissingPrivateSalt)
    );
    let private_commitment = logs.commitment_for_account(private_account, salt).unwrap();
    assert_ne!(private_commitment, logs.commitment());
    assert_ne!(
        private_commitment,
        logs.commitment_for_account(private_account, other_salt).unwrap()
    );
    assert_eq!(
        logs.commitment_for_account(public_account, Word::empty()).unwrap(),
        logs.commitment()
    );
    assert_eq!(
        TransactionLogs::default()
            .commitment_for_account(private_account, Word::empty())
            .unwrap(),
        Word::empty()
    );
}
