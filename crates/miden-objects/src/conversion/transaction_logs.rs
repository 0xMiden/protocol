use miden_protocol::transaction::{
    LogTopic,
    PublicTransactionLogBundle,
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

impl From<&PublicTransactionLogBundle> for proto::transaction::PublicTransactionLogBundle {
    fn from(value: &PublicTransactionLogBundle) -> Self {
        Self {
            transactions_commitment: Some(value.transactions_commitment().into()),
            entries: value
                .entries()
                .iter()
                .map(|(id, logs)| proto::transaction::PublicTransactionLogEntry {
                    transaction_id: Some((*id).into()),
                    logs: Some(logs.into()),
                })
                .collect(),
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
