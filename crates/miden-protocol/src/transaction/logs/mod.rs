//! Transaction logs, submitted data, and their ordered commitment.
//!
//! Individual transaction logs and ordered collections use distinct hash domains,
//! defined by [`ProtocolDomainRegistry::TransactionLog`] and
//! [`ProtocolDomainRegistry::TransactionLogs`].

use alloc::vec::Vec;

use crate::account::AccountId;
use crate::crypto::SequentialCommit;

mod topic;
pub use topic::LogTopic;

mod details;
pub use details::TransactionLogDetails;

#[cfg(test)]
mod tests;

use crate::{Felt, Hasher, ProtocolDomainRegistry, Word};

// ERRORS
// ================================================================================================

/// Errors from validating transaction logs or their submitted data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransactionLogError {
    /// An individual transaction log content exceeds its word limit.
    #[error(
        "log content has {0} words, exceeding the maximum of {max}",
        max = TransactionLog::MAX_NUM_WORDS
    )]
    TooManyContentWords(usize),
    /// The number of transaction logs exceeds the per transaction limit.
    #[error(
        "transaction has {0} logs, exceeding the maximum of {max}",
        max = TransactionLogs::MAX_COUNT
    )]
    TooManyLogs(usize),
    /// The combined contents exceed the transaction's word limit.
    #[error(
        "transaction log contents have {0} words, exceeding the maximum of {max}",
        max = TransactionLogs::MAX_NUM_WORDS
    )]
    TooManyTotalContentWords(usize),
    /// Submitted transaction log visibility differs from the native account.
    #[error("log data visibility does not match the native account")]
    VisibilityMismatch,
}

// TRANSACTION LOG
// ================================================================================================

/// A transaction log emitted by an account.
///
/// Construction validates content size; the kernel authenticates the emitter account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionLog {
    emitter: AccountId,
    topic: LogTopic,
    content: Vec<Word>,
}

impl TransactionLog {
    /// The maximum number of content words in a transaction log (8 KiB).
    pub const MAX_NUM_WORDS: usize = 256;

    /// Hash domain for individual transaction log commitments.
    const DOMAIN: Felt = ProtocolDomainRegistry::TransactionLog.as_felt();

    /// Creates a transaction log with the provided emitter, topic, and content.
    ///
    /// Returns an error if the content exceeds [`TransactionLog::MAX_NUM_WORDS`].
    pub fn new(
        emitter: AccountId,
        topic: LogTopic,
        content: Vec<Word>,
    ) -> Result<Self, TransactionLogError> {
        if content.len() > Self::MAX_NUM_WORDS {
            return Err(TransactionLogError::TooManyContentWords(content.len()));
        }
        Ok(Self { emitter, topic, content })
    }

    /// Returns the account that emitted this transaction log, which may be a foreign account.
    pub fn emitter(&self) -> AccountId {
        self.emitter
    }

    /// Returns the transaction log's application defined topic.
    pub fn topic(&self) -> LogTopic {
        self.topic
    }

    /// Returns the transaction log's content words.
    pub fn content(&self) -> &[Word] {
        &self.content
    }

    /// Returns the number of words in the content.
    pub fn num_content_words(&self) -> usize {
        self.content.len()
    }

    /// Hashes the content as field elements.
    ///
    /// The commitment of an empty content is [`Word::empty`].
    pub fn content_commitment(&self) -> Word {
        Hasher::hash_elements(Word::words_as_elements(&self.content))
    }

    /// Commits to the emitter, topic, and content commitment.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the emitter and topic word followed by the content commitment.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Consumes this transaction log and returns its emitter, topic, and content.
    pub fn into_parts(self) -> (AccountId, LogTopic, Vec<Word>) {
        (self.emitter, self.topic, self.content)
    }
}

impl SequentialCommit for TransactionLog {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let [topic_suffix, topic_prefix] = self.topic.as_elements();
        let mut elements = vec![
            self.emitter.suffix(),
            self.emitter.prefix().as_felt(),
            topic_suffix,
            topic_prefix,
        ];
        elements.extend_from_slice(self.content_commitment().as_elements());
        elements
    }

    fn to_commitment(&self) -> Word {
        Hasher::hash_elements_in_domain(&self.to_elements(), Self::DOMAIN)
    }
}

// TRANSACTION LOGS
// ================================================================================================

/// An immutable ordered collection of transaction logs with a cached commitment.
///
/// Construction computes the commitment once. Empty lists and duplicate transaction logs are
/// allowed.
///
/// # Commitment
///
/// Uses Poseidon2 over field elements. Each transaction log commits to its emitter, topic, and
/// content:
///
/// ```text
/// CONTENT_COMMITMENT = hash([CONTENT_WORD_0, CONTENT_WORD_1, ..., CONTENT_WORD_N])
/// METADATA = [emitter_suffix, emitter_prefix, topic_suffix, topic_prefix]
/// LOG_COMMITMENT = hash([METADATA, CONTENT_COMMITMENT], ProtocolDomainRegistry::TransactionLog)
/// ```
///
/// The collection commits to these log commitments in emission order:
///
/// ```text
/// hash([LOG_COMMITMENT_0, LOG_COMMITMENT_1, ..., LOG_COMMITMENT_N],
///      ProtocolDomainRegistry::TransactionLogs)
/// ```
///
/// The domains are defined by [`ProtocolDomainRegistry::TransactionLog`] and
/// [`ProtocolDomainRegistry::TransactionLogs`].
///
/// An empty collection has commitment [`Word::empty`]. The collection hash binds transaction log
/// order and duplicate occurrences. The content hash binds content and length.
///
/// These commitments do not hide predictable private transaction logs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TransactionLogs {
    logs: Vec<TransactionLog>,
    commitment: Word,
}

impl TransactionLogs {
    /// The maximum number of transaction logs emitted by a single transaction.
    pub const MAX_COUNT: usize = 64;

    /// The maximum combined content size, in words (16 KiB), excluding log metadata.
    pub const MAX_NUM_WORDS: usize = 512;

    /// Hash domain for ordered collections of transaction logs.
    const DOMAIN: Felt = ProtocolDomainRegistry::TransactionLogs.as_felt();

    /// Creates a collection from the provided transaction logs in emission order.
    ///
    /// Returns an error if the count exceeds [`TransactionLogs::MAX_COUNT`] or the total content
    /// size exceeds [`TransactionLogs::MAX_NUM_WORDS`].
    pub fn new(logs: Vec<TransactionLog>) -> Result<Self, TransactionLogError> {
        if logs.len() > Self::MAX_COUNT {
            return Err(TransactionLogError::TooManyLogs(logs.len()));
        }
        let num_content_words = logs.iter().map(TransactionLog::num_content_words).sum::<usize>();
        if num_content_words > Self::MAX_NUM_WORDS {
            return Err(TransactionLogError::TooManyTotalContentWords(num_content_words));
        }
        let mut result = Self { logs, commitment: Word::empty() };
        if !result.is_empty() {
            result.commitment =
                Hasher::hash_elements_in_domain(&result.to_elements(), Self::DOMAIN);
        }
        Ok(result)
    }

    /// Returns the commitment to the ordered transaction logs.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns individual log commitments as field elements, in emission order.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns the number of transaction logs.
    pub fn num_logs(&self) -> usize {
        self.logs.len()
    }

    /// Returns the total number of content words, excluding transaction log metadata.
    pub fn num_content_words(&self) -> usize {
        self.logs.iter().map(TransactionLog::num_content_words).sum()
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
}

impl SequentialCommit for TransactionLogs {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(self.logs.len() * Word::NUM_ELEMENTS);
        for log in &self.logs {
            elements.extend_from_slice(log.to_commitment().as_elements());
        }
        elements
    }

    fn to_commitment(&self) -> Word {
        self.commitment
    }
}

const _: () = assert!(TransactionLogs::MAX_NUM_WORDS >= TransactionLog::MAX_NUM_WORDS);
