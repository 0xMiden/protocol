use alloc::string::ToString;
use alloc::vec::Vec;

#[cfg(any(test, feature = "testing"))]
use crate::Word;
use crate::transaction::{OrderedTransactionHeaders, TransactionLogData, TransactionLogError};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{
    MAX_LOG_DATA_BYTES_PER_BATCH,
    MAX_LOG_DATA_BYTES_PER_BLOCK,
    MAX_LOG_DATA_TRANSACTIONS_PER_BATCH,
    MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
    MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
    MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
    MAX_PUBLIC_LOGS_PER_BATCH,
    MAX_PUBLIC_LOGS_PER_BLOCK,
};

// The collection count and each entry's byte length are encoded as u32 values.
const LENGTH_PREFIX_SIZE: usize = size_of::<u32>();

/// Submitted transaction log data in transaction header order.
///
/// Contains exactly one entry per transaction, including transactions with no transaction logs.
/// Public entries contain complete transaction logs; private entries contain only commitments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionLogDataCollection(Vec<TransactionLogData>);

#[derive(Clone, Copy)]
enum LogDataScope {
    Batch,
    Block,
}

struct LogDataBudget {
    entries: usize,
    bytes: usize,
    public_logs: usize,
    payload_words: usize,
}

impl LogDataScope {
    fn budget(self) -> LogDataBudget {
        match self {
            Self::Batch => LogDataBudget {
                entries: MAX_LOG_DATA_TRANSACTIONS_PER_BATCH,
                bytes: MAX_LOG_DATA_BYTES_PER_BATCH - LENGTH_PREFIX_SIZE,
                public_logs: MAX_PUBLIC_LOGS_PER_BATCH,
                payload_words: MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
            },
            Self::Block => LogDataBudget {
                entries: MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
                bytes: MAX_LOG_DATA_BYTES_PER_BLOCK - LENGTH_PREFIX_SIZE,
                public_logs: MAX_PUBLIC_LOGS_PER_BLOCK,
                payload_words: MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
            },
        }
    }
}

impl LogDataBudget {
    fn consume(&mut self, data: &TransactionLogData) -> Result<(), TransactionLogError> {
        self.entries = self.entries.checked_sub(1).ok_or(TransactionLogError::AggregateBudget)?;
        self.bytes = self
            .bytes
            .checked_sub(LENGTH_PREFIX_SIZE + data.get_size_hint())
            .ok_or(TransactionLogError::AggregateBudget)?;
        if let TransactionLogData::Public(logs) = data {
            self.public_logs = self
                .public_logs
                .checked_sub(logs.num_logs())
                .ok_or(TransactionLogError::AggregateBudget)?;
            self.payload_words = self
                .payload_words
                .checked_sub(logs.num_payload_words())
                .ok_or(TransactionLogError::AggregateBudget)?;
        }
        Ok(())
    }
}

impl TransactionLogDataCollection {
    /// Creates submitted transaction log data within the block resource limits.
    ///
    /// Call [`Self::validate_for_block`] or [`Self::validate_for_batch`] to check each entry
    /// against its transaction header.
    pub fn new(data: Vec<TransactionLogData>) -> Result<Self, TransactionLogError> {
        let collection = Self(data);
        Self::validate_block_budget(collection.0.iter())?;
        Ok(collection)
    }

    /// Returns submitted transaction log data in transaction order.
    pub fn as_slice(&self) -> &[TransactionLogData] {
        &self.0
    }

    /// Consumes the collection and returns submitted transaction log data in transaction order.
    pub fn into_vec(self) -> Vec<TransactionLogData> {
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
            if data.commitment() != header.logs_commitment() {
                return Err(TransactionLogError::CommitmentMismatch(index));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_batch_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogData>,
    ) -> Result<(), TransactionLogError> {
        Self::validate_budget(entries, LogDataScope::Batch)
    }

    pub(crate) fn validate_block_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogData>,
    ) -> Result<(), TransactionLogError> {
        Self::validate_budget(entries, LogDataScope::Block)
    }

    fn validate_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogData>,
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
                        TransactionLogData::Public(Default::default())
                    } else {
                        TransactionLogData::Private(Word::empty())
                    }
                })
                .collect(),
        )
    }
}

impl Serializable for TransactionLogDataCollection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0.len() as u32);
        for data in &self.0 {
            target.write_u32(data.get_size_hint() as u32);
            data.write_into(target);
        }
    }

    fn get_size_hint(&self) -> usize {
        LENGTH_PREFIX_SIZE
            + self
                .0
                .iter()
                .map(|data| LENGTH_PREFIX_SIZE + data.get_size_hint())
                .sum::<usize>()
    }
}

impl Deserializable for TransactionLogDataCollection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_u32()? as usize;
        if count > MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK {
            return Err(DeserializationError::InvalidValue(
                "too many transaction log data entries".into(),
            ));
        }
        let max_transaction_size = TransactionLogData::max_serialized_size();
        let mut budget = LogDataScope::Block.budget();
        let mut data = Vec::new();
        for _ in 0..count {
            let size = source.read_u32()? as usize;
            if budget
                .bytes
                .checked_sub(LENGTH_PREFIX_SIZE)
                .is_none_or(|remaining| size > remaining)
            {
                return Err(DeserializationError::InvalidValue(
                    "transaction log data exceeds block byte budget".into(),
                ));
            }
            // Reject oversized frames before reading or allocating their payloads.
            if size > max_transaction_size {
                return Err(DeserializationError::InvalidValue(
                    "transaction log data frame exceeds transaction limit".into(),
                ));
            }
            let encoded = source.read_slice(size)?;
            let entry = TransactionLogData::read_from_bytes(encoded)?;
            if entry.get_size_hint() != size {
                return Err(DeserializationError::InvalidValue(
                    "noncanonical transaction log data frame".into(),
                ));
            }
            budget
                .consume(&entry)
                .map_err(|error| DeserializationError::InvalidValue(error.to_string()))?;
            data.push(entry);
        }
        Ok(Self(data))
    }
}

#[cfg(test)]
mod tests;
