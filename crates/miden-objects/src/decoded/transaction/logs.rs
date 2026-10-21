pub use proto::transaction::{
    DecodedLogTopic as LogTopic,
    DecodedTransactionLog as TransactionLog,
    DecodedTransactionLogDetails as TransactionLogDetails,
    DecodedTransactionLogs as TransactionLogs,
};

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for LogTopic {
    type Verified = miden_protocol::transaction::LogTopic;
    type Error = core::convert::Infallible;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.suffix, self.prefix))
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
