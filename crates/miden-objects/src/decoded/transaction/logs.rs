use miden_protocol::transaction::TransactionLogError;
pub use proto::transaction::{
    DecodedLogTopic as LogTopic,
    DecodedTransactionLog as TransactionLog,
    DecodedTransactionLogDetails as TransactionLogDetails,
    DecodedTransactionLogs as TransactionLogs,
};

use crate::decoded::VerificationError;
use crate::{Verify, proto};

impl Verify for LogTopic {
    type Verified = miden_protocol::transaction::LogTopic;
    type Error = core::convert::Infallible;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new([self.suffix, self.prefix]))
    }
}

impl Verify for TransactionLog {
    type Verified = miden_protocol::transaction::TransactionLog;
    type Error = VerificationError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.emitter.verify()?,
            miden_protobuf::unwrap_infallible(self.topic.verify()),
            self.content.into_inner(),
        )?)
    }
}

impl Verify for TransactionLogs {
    type Verified = miden_protocol::transaction::TransactionLogs;
    type Error = VerificationError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let logs = self.logs.as_slice();
        if logs.len() > Self::Verified::MAX_COUNT {
            return Err(TransactionLogError::TooManyLogs(logs.len()).into());
        }
        let mut total_words = 0;
        for log in logs {
            let count = log.content.as_slice().len();
            if count > miden_protocol::transaction::TransactionLog::MAX_NUM_WORDS {
                return Err(TransactionLogError::TooManyContentWords(count).into());
            }
            total_words += count;
            if total_words > Self::Verified::MAX_NUM_WORDS {
                return Err(TransactionLogError::TooManyTotalContentWords(total_words).into());
            }
        }
        Ok(Self::Verified::new(self.logs.verify()?)?)
    }
}

impl Verify for TransactionLogDetails {
    type Verified = miden_protocol::transaction::TransactionLogDetails;
    type Error = VerificationError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::transaction::transaction_log_details::DecodedVisibility;
        match self.visibility {
            DecodedVisibility::Private(commitment) => Ok(Self::Verified::Private(commitment)),
            DecodedVisibility::Public(logs) => Ok(Self::Verified::Public(logs.verify()?)),
        }
    }
}

#[cfg(test)]
mod tests;

pub use proto::transaction::DecodedTransactionLogDetailsCollection as TransactionLogDetailsCollection;

impl TransactionLogDetailsCollection {
    pub(crate) fn verify_for_batch(
        self,
    ) -> Result<miden_protocol::transaction::TransactionLogDetailsCollection, VerificationError>
    {
        self.verify_with_limits(
            miden_protocol::MAX_LOG_DATA_TRANSACTIONS_PER_BATCH,
            miden_protocol::MAX_PUBLIC_LOGS_PER_BATCH,
            miden_protocol::MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
            miden_protocol::MAX_LOG_DATA_BYTES_PER_BATCH,
        )
    }

    fn verify_with_limits(
        self,
        max_entries: usize,
        mut remaining_logs: usize,
        mut remaining_words: usize,
        mut remaining_bytes: usize,
    ) -> Result<miden_protocol::transaction::TransactionLogDetailsCollection, VerificationError>
    {
        use prost::Message;
        if self.entries.as_slice().len() > max_entries {
            return Err(TransactionLogError::AggregateBudget.into());
        }
        // Stop constructing and hashing entries as soon as an aggregate budget is exhausted.
        let entries = self.entries.try_map(|entry| -> Result<_, VerificationError> {
            let entry = entry.verify()?;
            if let miden_protocol::transaction::TransactionLogDetails::Public(logs) = &entry {
                remaining_logs = remaining_logs
                    .checked_sub(logs.num_logs())
                    .ok_or(TransactionLogError::AggregateBudget)?;
                remaining_words = remaining_words
                    .checked_sub(logs.num_content_words())
                    .ok_or(TransactionLogError::AggregateBudget)?;
            }
            // A repeated protobuf field is the concatenation of its individually framed entries.
            let encoded_len = proto::transaction::TransactionLogDetailsCollection {
                entries: alloc::vec![(&entry).into()],
            }
            .encoded_len();
            remaining_bytes = remaining_bytes
                .checked_sub(encoded_len)
                .ok_or(TransactionLogError::AggregateBudget)?;
            Ok(entry)
        })?;
        Ok(miden_protocol::transaction::TransactionLogDetailsCollection::new(entries)?)
    }
}

impl Verify for TransactionLogDetailsCollection {
    type Verified = miden_protocol::transaction::TransactionLogDetailsCollection;
    type Error = VerificationError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.verify_with_limits(
            miden_protocol::MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
            miden_protocol::MAX_PUBLIC_LOGS_PER_BLOCK,
            miden_protocol::MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
            miden_protocol::MAX_LOG_DATA_BYTES_PER_BLOCK,
        )
    }
}
