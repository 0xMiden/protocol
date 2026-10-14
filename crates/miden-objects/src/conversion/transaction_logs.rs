use miden_protocol::transaction::{
    LogTopic,
    TransactionLog,
    TransactionLogDetails,
    TransactionLogs,
};

use crate::proto;

impl From<LogTopic> for proto::transaction::LogTopic {
    fn from(value: LogTopic) -> Self {
        Self {
            suffix: Some(value.suffix().into()),
            prefix: Some(value.prefix().into()),
        }
    }
}

impl From<&TransactionLog> for proto::transaction::TransactionLog {
    fn from(value: &TransactionLog) -> Self {
        Self {
            emitter: Some(value.emitter().into()),
            topic: Some(value.topic().into()),
            content: value.content().iter().map(Into::into).collect(),
        }
    }
}

impl From<&TransactionLogs> for proto::transaction::TransactionLogs {
    fn from(value: &TransactionLogs) -> Self {
        Self {
            logs: value.iter().map(Into::into).collect(),
        }
    }
}

impl From<&TransactionLogDetails> for proto::transaction::TransactionLogDetails {
    fn from(value: &TransactionLogDetails) -> Self {
        use proto::transaction::transaction_log_details::Visibility;
        let visibility = match value {
            TransactionLogDetails::Private(commitment) => Visibility::Private(commitment.into()),
            TransactionLogDetails::Public(logs) => Visibility::Public(logs.into()),
        };
        Self { visibility: Some(visibility) }
    }
}

impl From<&miden_protocol::transaction::TransactionLogDetailsCollection>
    for proto::transaction::TransactionLogDetailsCollection
{
    fn from(value: &miden_protocol::transaction::TransactionLogDetailsCollection) -> Self {
        Self {
            entries: value.as_slice().iter().map(Into::into).collect(),
        }
    }
}
