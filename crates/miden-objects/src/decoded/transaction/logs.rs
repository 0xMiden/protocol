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
