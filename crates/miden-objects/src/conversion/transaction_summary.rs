use miden_protocol::transaction::TransactionSummary;

use crate::proto;

#[cfg(test)]
mod tests;

// TRANSACTION SUMMARY
// ================================================================================================

impl From<&TransactionSummary> for proto::transaction::TransactionSummaryV1 {
    fn from(summary: &TransactionSummary) -> Self {
        Self {
            account_delta: Some(summary.account_delta().into()),
            input_notes: Some(summary.input_notes().into()),
            output_notes: Some(summary.output_notes().into()),
            block_number: Some(summary.block_number().into()),
            block_commitment: Some(summary.block_commitment().into()),
            expiration_delta: summary.expiration_delta().into(),
            user_params: summary.user_params().as_elements().iter().map(Into::into).collect(),
            logs: Some(summary.logs().into()),
        }
    }
}

impl From<&TransactionSummary> for proto::transaction::TransactionSummary {
    fn from(summary: &TransactionSummary) -> Self {
        use proto::transaction::transaction_summary::Version;

        Self {
            version: Some(Version::V1(summary.into())),
        }
    }
}

impl From<TransactionSummary> for proto::transaction::TransactionSummary {
    fn from(summary: TransactionSummary) -> Self {
        Self::from(&summary)
    }
}
