use super::{TransactionLog, TransactionLogs};

// ERRORS
// ================================================================================================

/// Errors from validating transaction logs or their submitted data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransactionLogError {
    #[error("public logs exceed their aggregate resource limits")]
    PublicLogsLimitExceeded,
    #[error("public log entries do not match the ordered public transactions")]
    PublicLogsAssociationMismatch,
    #[error("public logs do not match the transaction commitments")]
    PublicLogsCommitmentMismatch,
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
