use alloc::vec::Vec;

#[cfg(any(test, feature = "testing"))]
use crate::Word;
use crate::transaction::{OrderedTransactionHeaders, TransactionLogDetails, TransactionLogError};
use crate::{
    MAX_LOG_DATA_TRANSACTIONS_PER_BATCH,
    MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
    MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
    MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
    MAX_PUBLIC_LOGS_PER_BATCH,
    MAX_PUBLIC_LOGS_PER_BLOCK,
};

/// Submitted transaction log data in transaction header order.
///
/// Contains exactly one entry per transaction, including transactions with no transaction logs.
/// Public entries contain complete transaction logs; private entries contain only commitments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionLogDetailsCollection(Vec<TransactionLogDetails>);

#[derive(Clone, Copy)]
enum LogDataScope {
    Batch,
    Block,
}

struct LogDataBudget {
    entries: usize,
    public_logs: usize,
    payload_words: usize,
}

impl LogDataScope {
    fn budget(self) -> LogDataBudget {
        match self {
            Self::Batch => LogDataBudget {
                entries: MAX_LOG_DATA_TRANSACTIONS_PER_BATCH,
                public_logs: MAX_PUBLIC_LOGS_PER_BATCH,
                payload_words: MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
            },
            Self::Block => LogDataBudget {
                entries: MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
                public_logs: MAX_PUBLIC_LOGS_PER_BLOCK,
                payload_words: MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
            },
        }
    }
}

impl LogDataBudget {
    fn consume(&mut self, data: &TransactionLogDetails) -> Result<(), TransactionLogError> {
        self.entries = self.entries.checked_sub(1).ok_or(TransactionLogError::AggregateBudget)?;
        if let TransactionLogDetails::Public(logs) = data {
            self.public_logs = self
                .public_logs
                .checked_sub(logs.num_logs())
                .ok_or(TransactionLogError::AggregateBudget)?;
            self.payload_words = self
                .payload_words
                .checked_sub(logs.num_content_words())
                .ok_or(TransactionLogError::AggregateBudget)?;
        }
        Ok(())
    }
}

impl TransactionLogDetailsCollection {
    /// Creates submitted transaction log data within the block resource limits.
    ///
    /// Call [`Self::validate_for_block`] or [`Self::validate_for_batch`] to check each entry
    /// against its transaction header.
    pub fn new(data: Vec<TransactionLogDetails>) -> Result<Self, TransactionLogError> {
        let collection = Self(data);
        Self::validate_block_budget(collection.0.iter())?;
        Ok(collection)
    }

    /// Returns submitted transaction log data in transaction order.
    pub fn as_slice(&self) -> &[TransactionLogDetails] {
        &self.0
    }

    /// Consumes the collection and returns submitted transaction log data in transaction order.
    pub fn into_vec(self) -> Vec<TransactionLogDetails> {
        self.0
    }

    /// Checks header associations, visibility, commitments, and batch limits.
    pub fn validate_for_batch(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogError> {
        Self::validate_batch_budget(self.0.iter())?;
        self.validate_headers(headers)
    }

    /// Checks header associations, visibility, commitments, and block limits.
    pub fn validate_for_block(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogError> {
        Self::validate_block_budget(self.0.iter())?;
        self.validate_headers(headers)
    }

    fn validate_headers(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogError> {
        if self.0.len() != headers.as_slice().len() {
            return Err(TransactionLogError::AssociationCount);
        }
        for (index, (data, header)) in self.0.iter().zip(headers.as_slice()).enumerate() {
            data.validate_visibility(header.account_id())?;
            if data.to_commitment() != header.logs_commitment() {
                return Err(TransactionLogError::CommitmentMismatch(index));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_batch_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogDetails>,
    ) -> Result<(), TransactionLogError> {
        Self::validate_budget(entries, LogDataScope::Batch)
    }

    pub(crate) fn validate_block_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogDetails>,
    ) -> Result<(), TransactionLogError> {
        Self::validate_budget(entries, LogDataScope::Block)
    }

    fn validate_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogDetails>,
        scope: LogDataScope,
    ) -> Result<(), TransactionLogError> {
        let mut budget = scope.budget();
        for data in entries {
            budget.consume(data)?;
        }
        Ok(())
    }

    /// Builds empty fixture data and refuses headers that commit to nonempty transaction logs.
    #[cfg(any(test, feature = "testing"))]
    pub fn empty_for_headers(headers: &OrderedTransactionHeaders) -> Self {
        Self(
            headers
                .as_slice()
                .iter()
                .map(|header| {
                    assert!(
                        header.logs_commitment().is_empty(),
                        "fixture header has nonempty transaction logs"
                    );
                    if header.account_id().is_public() {
                        TransactionLogDetails::Public(Default::default())
                    } else {
                        TransactionLogDetails::Private(Word::empty())
                    }
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests;
