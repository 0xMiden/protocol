//! Transaction logs, submitted data, and their ordered commitment.
//!
//! Individual transaction logs and ordered collections use distinct hash domains,
//! defined by [`TransactionLog::COMMITMENT_DOMAIN`] and
//! [`TransactionLogs::COMMITMENT_DOMAIN`].

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::account::AccountId;
use crate::utils::sync::OnceLockCompat;

mod topic;
pub use topic::LogTopic;

mod data;
pub use data::TransactionLogData;

use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{
    Felt,
    Hasher,
    MAX_LOG_PAYLOAD_WORDS,
    MAX_LOG_PAYLOAD_WORDS_PER_TX,
    MAX_LOGS_PER_TX,
    Word,
};

// ERRORS
// ================================================================================================

/// Errors from validating transaction logs or their submitted data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransactionLogError {
    /// An individual transaction log payload exceeds its word limit.
    #[error("log payload has {0} words, exceeding the maximum of {MAX_LOG_PAYLOAD_WORDS}")]
    TooManyPayloadWords(usize),
    /// The number of transaction logs exceeds the per transaction limit.
    #[error("transaction has {0} logs, exceeding the maximum of {MAX_LOGS_PER_TX}")]
    TooManyLogs(usize),
    /// The combined payloads exceed the transaction's word limit.
    #[error(
        "transaction log payloads have {0} words, exceeding the maximum of {MAX_LOG_PAYLOAD_WORDS_PER_TX}"
    )]
    TooManyTotalPayloadWords(usize),
    /// Submitted transaction log visibility differs from the native account.
    #[error("log data visibility does not match the native account")]
    VisibilityMismatch,
}

// TRANSACTION LOG
// ================================================================================================

/// A transaction log emitted by an account.
///
/// Construction validates payload size; the kernel authenticates the emitter account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionLog {
    emitter: AccountId,
    topic: LogTopic,
    payload: Vec<Word>,
}

impl TransactionLog {
    /// Hash domain for individual transaction log commitments.
    pub const COMMITMENT_DOMAIN: Felt = Felt::new_unchecked(0x02_0005);

    /// Creates a transaction log with the provided emitter, topic, and payload.
    ///
    /// Returns an error if the payload exceeds [`MAX_LOG_PAYLOAD_WORDS`].
    pub fn new(
        emitter: AccountId,
        topic: LogTopic,
        payload: Vec<Word>,
    ) -> Result<Self, TransactionLogError> {
        Self::validate_payload_size(payload.len())?;
        Ok(Self { emitter, topic, payload })
    }

    /// Returns the account that emitted this transaction log, which may be a foreign account.
    pub fn emitter(&self) -> AccountId {
        self.emitter
    }

    /// Returns the transaction log's application defined topic.
    pub fn topic(&self) -> LogTopic {
        self.topic
    }

    /// Returns the transaction log's payload words.
    pub fn payload(&self) -> &[Word] {
        &self.payload
    }

    /// Returns the number of words in the payload.
    pub fn num_payload_words(&self) -> usize {
        self.payload.len()
    }

    /// Hashes the payload as field elements.
    ///
    /// The commitment of an empty payload is [`Word::empty`].
    pub fn payload_commitment(&self) -> Word {
        Hasher::hash_elements(Word::words_as_elements(&self.payload))
    }

    /// Commits to the emitter, topic, and payload commitment.
    pub fn commitment(&self) -> Word {
        let [topic_0, topic_1] = self.topic.as_elements();
        let metadata =
            Word::new([self.emitter.suffix(), self.emitter.prefix().as_felt(), topic_0, topic_1]);
        Hasher::merge_in_domain(&[metadata, self.payload_commitment()], Self::COMMITMENT_DOMAIN)
    }

    /// Consumes this transaction log and returns its emitter, topic, and payload.
    pub fn into_parts(self) -> (AccountId, LogTopic, Vec<Word>) {
        (self.emitter, self.topic, self.payload)
    }

    fn validate_payload_size(num_words: usize) -> Result<(), TransactionLogError> {
        if num_words > MAX_LOG_PAYLOAD_WORDS {
            return Err(TransactionLogError::TooManyPayloadWords(num_words));
        }
        Ok(())
    }

    /// Checks both payload limits before the reader can allocate or read the payload words.
    fn read_with_payload_budget<R: ByteReader>(
        source: &mut R,
        previous_payload_words: usize,
    ) -> Result<Self, DeserializationError> {
        let emitter = AccountId::read_from(source)?;
        let topic = LogTopic::read_from(source)?;
        let num_words = usize::from(source.read_u16()?);
        Self::validate_payload_size(num_words)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        TransactionLogs::validate_total_payload_size(previous_payload_words + num_words)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        let payload = source.read_many_iter::<Word>(num_words)?.collect::<Result<_, _>>()?;
        Self::new(emitter, topic, payload)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

impl Serializable for TransactionLog {
    /// Writes the emitter, topic, payload word count as a little-endian u16, and payload words.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.emitter.write_into(target);
        self.topic.write_into(target);
        target.write_u16(self.payload.len() as u16);
        target.write_many(&self.payload);
    }

    fn get_size_hint(&self) -> usize {
        Self::min_serialized_size() + self.payload.len() * Word::SERIALIZED_SIZE
    }
}

impl Deserializable for TransactionLog {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::read_with_payload_budget(source, 0)
    }

    fn min_serialized_size() -> usize {
        AccountId::SERIALIZED_SIZE + LogTopic::SERIALIZED_SIZE + size_of::<u16>()
    }
}

// TRANSACTION LOGS
// ================================================================================================

/// An ordered collection of transaction logs with a cached commitment.
///
/// Appending invalidates the cache. Empty lists and duplicate transaction logs are allowed.
///
/// # Commitment
///
/// Uses Poseidon2 over field elements. For transaction logs numbered `1..=n`:
///
/// ```text
/// P_i = hash_elements(flatten(payload_i))
/// M_i = [emitter_suffix, emitter_prefix, topic_0, topic_1]
/// L_i = merge_in_domain([M_i, P_i], TransactionLog::COMMITMENT_DOMAIN)
/// commitment = hash_elements_in_domain(L_1 || ... || L_n, TransactionLogs::COMMITMENT_DOMAIN)
/// ```
///
/// The domains are defined by [`TransactionLog::COMMITMENT_DOMAIN`] and
/// [`TransactionLogs::COMMITMENT_DOMAIN`].
///
/// An empty collection has commitment [`Word::empty`]. The collection hash binds transaction log
/// order and duplicate occurrences. The payload hash binds content and length.
///
/// These commitments do not hide predictable private transaction logs.
#[derive(Debug, Default)]
pub struct TransactionLogs {
    logs: Vec<TransactionLog>,
    log_commitments: Vec<Word>,
    commitment: OnceLockCompat<Word>,
}

impl TransactionLogs {
    /// Hash domain for ordered collections of transaction logs.
    pub const COMMITMENT_DOMAIN: Felt = Felt::new_unchecked(0x02_0003);

    /// Creates a collection by appending the provided transaction logs in order.
    ///
    /// Returns an error if the count exceeds [`MAX_LOGS_PER_TX`] or the total payload size
    /// exceeds [`MAX_LOG_PAYLOAD_WORDS_PER_TX`].
    pub fn new(logs: Vec<TransactionLog>) -> Result<Self, TransactionLogError> {
        Self::validate_log_count(logs.len())?;
        let mut result = Self::default();
        for log in logs {
            result.try_push(log)?;
        }
        Ok(result)
    }

    /// Appends a transaction log and invalidates the cached collection commitment.
    ///
    /// Returns an error if the resulting count exceeds [`MAX_LOGS_PER_TX`] or total payload
    /// size exceeds [`MAX_LOG_PAYLOAD_WORDS_PER_TX`]. On error the collection is unchanged.
    pub fn try_push(&mut self, log: TransactionLog) -> Result<(), TransactionLogError> {
        let num_logs = self.logs.len() + 1;
        Self::validate_log_count(num_logs)?;
        Self::validate_total_payload_size(self.num_payload_words() + log.num_payload_words())?;

        let commitment = log.commitment();
        self.logs.push(log);
        self.log_commitments.push(commitment);
        self.commitment.reset();
        Ok(())
    }

    /// Returns the commitment to the ordered transaction logs.
    pub fn commitment(&self) -> Word {
        *self.commitment.get_or_init(|| {
            if self.is_empty() {
                Word::empty()
            } else {
                Hasher::hash_elements_in_domain(
                    Word::words_as_elements(&self.log_commitments),
                    Self::COMMITMENT_DOMAIN,
                )
            }
        })
    }

    /// Returns the number of transaction logs.
    pub fn num_logs(&self) -> usize {
        self.logs.len()
    }

    /// Returns the total number of payload words, excluding transaction log metadata.
    pub fn num_payload_words(&self) -> usize {
        self.logs.iter().map(TransactionLog::num_payload_words).sum()
    }

    /// Returns whether the collection contains no transaction logs.
    pub fn is_empty(&self) -> bool {
        self.logs.is_empty()
    }

    /// Returns the transaction logs in emission order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &TransactionLog> {
        self.logs.iter()
    }

    /// Consumes this collection and returns the transaction logs in emission order.
    pub fn into_vec(self) -> Vec<TransactionLog> {
        self.logs
    }

    fn validate_log_count(num_logs: usize) -> Result<(), TransactionLogError> {
        if num_logs > MAX_LOGS_PER_TX {
            return Err(TransactionLogError::TooManyLogs(num_logs));
        }
        Ok(())
    }

    fn validate_total_payload_size(num_words: usize) -> Result<(), TransactionLogError> {
        if num_words > MAX_LOG_PAYLOAD_WORDS_PER_TX {
            return Err(TransactionLogError::TooManyTotalPayloadWords(num_words));
        }
        Ok(())
    }
}

impl Clone for TransactionLogs {
    fn clone(&self) -> Self {
        let commitment = OnceLockCompat::new();
        if let Some(value) = self.commitment.get() {
            commitment.get_or_init(|| *value);
        }
        Self {
            logs: self.logs.clone(),
            log_commitments: self.log_commitments.clone(),
            commitment,
        }
    }
}

impl PartialEq for TransactionLogs {
    fn eq(&self, other: &Self) -> bool {
        self.logs == other.logs
    }
}

impl Eq for TransactionLogs {}

impl IntoIterator for TransactionLogs {
    type Item = TransactionLog;
    type IntoIter = alloc::vec::IntoIter<TransactionLog>;

    fn into_iter(self) -> Self::IntoIter {
        self.logs.into_iter()
    }
}

impl<'a> IntoIterator for &'a TransactionLogs {
    type Item = &'a TransactionLog;
    type IntoIter = core::slice::Iter<'a, TransactionLog>;

    fn into_iter(self) -> Self::IntoIter {
        self.logs.iter()
    }
}

impl Serializable for TransactionLogs {
    /// Writes a little endian u16 transaction log count followed by the contents, without the
    /// commitment.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.logs.len() as u16);
        target.write_many(&self.logs);
    }

    fn get_size_hint(&self) -> usize {
        size_of::<u16>() + self.logs.iter().map(Serializable::get_size_hint).sum::<usize>()
    }
}

impl Deserializable for TransactionLogs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_logs = usize::from(source.read_u16()?);
        Self::validate_log_count(num_logs)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        let mut logs = Self::default();
        for _ in 0..num_logs {
            let log = TransactionLog::read_with_payload_budget(source, logs.num_payload_words())?;
            logs.try_push(log)
                .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        }
        Ok(logs)
    }

    fn min_serialized_size() -> usize {
        size_of::<u16>()
    }
}

#[cfg(test)]
mod tests;
