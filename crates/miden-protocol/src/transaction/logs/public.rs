use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::{TransactionLogDetails, TransactionLogError, TransactionLogs};
use crate::batch::ProposedBatch;
use crate::transaction::{OrderedTransactionHeaders, TransactionHeader, TransactionId};

/// Aggregate public-log limits enforced by batch and block construction, not by the kernels.
#[derive(Debug, Clone, Copy)]
pub struct PublicLogLimits {
    transactions: usize,
    logs: usize,
    content_words: usize,
}

impl PublicLogLimits {
    /// Maximum batch transaction, public record, and content-word counts.
    pub const BATCH: Self = Self {
        transactions: 1024,
        logs: 4096,
        content_words: 65_536,
    };
    /// Maximum block transaction, public record, and content-word counts.
    pub const BLOCK: Self = Self {
        transactions: 65_536,
        logs: 65_536,
        content_words: 524_288,
    };

    /// Maximum transaction count, including private transactions and empty log collections.
    pub const fn transactions(self) -> usize {
        self.transactions
    }
    /// Maximum public log record count.
    pub const fn logs(self) -> usize {
        self.logs
    }
    /// Maximum public content-word count.
    pub const fn content_words(self) -> usize {
        self.content_words
    }

    /// Checks aggregate counts, including private and empty-log transactions.
    ///
    /// # Errors
    /// Returns [`TransactionLogError::PublicLogsLimitExceeded`] if any count exceeds its limit.
    pub fn check(
        self,
        transactions: usize,
        logs: usize,
        content_words: usize,
    ) -> Result<(), TransactionLogError> {
        if transactions > self.transactions
            || logs > self.logs
            || content_words > self.content_words
        {
            return Err(TransactionLogError::PublicLogsLimitExceeded);
        }
        Ok(())
    }

    /// Checks public collections without copying their payloads.
    ///
    /// # Errors
    /// Returns [`TransactionLogError::PublicLogsLimitExceeded`] on an excessive aggregate count.
    pub fn check_logs<'a>(
        self,
        transactions: usize,
        logs: impl IntoIterator<Item = &'a TransactionLogs>,
    ) -> Result<(), TransactionLogError> {
        self.check(transactions, 0, 0)?;
        let (mut records, mut words) = (0usize, 0usize);
        for logs in logs {
            records = records
                .checked_add(logs.num_logs())
                .ok_or(TransactionLogError::PublicLogsLimitExceeded)?;
            words = words
                .checked_add(logs.num_content_words())
                .ok_or(TransactionLogError::PublicLogsLimitExceeded)?;
            self.check(transactions, records, words)?;
        }
        Ok(())
    }
}

/// Complete public log collections in native transaction order.
///
/// Each public native-account transaction has one entry, including empty collections. Private
/// transactions have none, even when they call public foreign accounts. Duplicate logs are
/// retained. The enclosing batch/block headers already commit to these payloads; there is no
/// separate root. Validation checks consistency with headers, not their authenticity. Owners
/// enforce their own aggregate limits and must revalidate the association with their own headers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublicTransactionLogs {
    entries: Vec<(TransactionId, TransactionLogs)>,
}

impl PublicTransactionLogs {
    /// Associates complete public logs with ordered transaction headers.
    ///
    /// # Errors
    /// Rejects missing, extra, duplicated or reordered associations, private entries, and payloads
    /// that do not match the header's log commitment.
    pub fn new(
        entries: Vec<(TransactionId, TransactionLogs)>,
        headers: &OrderedTransactionHeaders,
    ) -> Result<Self, TransactionLogError> {
        let logs = Self { entries };
        logs.validate_entries(headers.as_slice().iter())?;
        Ok(logs)
    }

    /// Associates complete public logs with grouped block transaction headers.
    ///
    /// # Errors
    /// Rejects invalid associations, payload commitments, or aggregate block counts.
    pub fn new_for_block(
        entries: Vec<(TransactionId, TransactionLogs)>,
        headers: &[OrderedTransactionHeaders],
    ) -> Result<Self, TransactionLogError> {
        let logs = Self { entries };
        logs.validate_for_block(headers)?;
        Ok(logs)
    }

    /// Copies public logs from the full transactions of a validated proposal.
    ///
    /// # Errors
    /// Rejects excessive batch counts or inconsistent transaction headers.
    pub fn from_batch(batch: &ProposedBatch) -> Result<Self, TransactionLogError> {
        let entries = batch
            .transactions()
            .iter()
            .filter_map(|tx| match tx.log_details() {
                TransactionLogDetails::Public(logs) => Some((tx.id(), logs.clone())),
                TransactionLogDetails::Private(_) => None,
            })
            .collect();
        let logs = Self::new(entries, &batch.transaction_headers())?;
        logs.validate_for_batch(&batch.transaction_headers())?;
        Ok(logs)
    }

    /// Public log lists in transaction order, keyed by transaction ID.
    pub fn entries(&self) -> &[(TransactionId, TransactionLogs)] {
        &self.entries
    }

    /// Consumes this collection, preserving transaction and emission order.
    pub fn into_entries(self) -> Vec<(TransactionId, TransactionLogs)> {
        self.entries
    }

    /// Concatenates already-associated collections in their owners' transaction order.
    /// The enclosing block proposal checks aggregate bounds and uniqueness across batches.
    pub(crate) fn concatenate(logs: impl IntoIterator<Item = Self>) -> Self {
        Self {
            entries: logs.into_iter().flat_map(Self::into_entries).collect(),
        }
    }

    /// Checks completeness, visibility, association, commitments and batch limits.
    ///
    /// # Errors
    /// Rejects an invalid association, payload hash, or aggregate count.
    pub fn validate_for_batch(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogError> {
        self.validate(headers.as_slice().iter(), PublicLogLimits::BATCH)
    }

    /// Checks completeness, visibility, association, commitments and block limits.
    ///
    /// # Errors
    /// Rejects an invalid association, payload hash, or aggregate count.
    pub fn validate_for_block(
        &self,
        headers: &[OrderedTransactionHeaders],
    ) -> Result<(), TransactionLogError> {
        self.validate(headers.iter().flat_map(|batch| batch.as_slice()), PublicLogLimits::BLOCK)
    }

    fn validate<'a>(
        &self,
        headers: impl Iterator<Item = &'a TransactionHeader> + Clone,
        limits: PublicLogLimits,
    ) -> Result<(), TransactionLogError> {
        limits.check_logs(
            headers.clone().count().max(self.entries.len()),
            self.entries.iter().map(|(_, logs)| logs),
        )?;
        self.validate_entries(headers)
    }

    fn validate_entries<'a>(
        &self,
        headers: impl Iterator<Item = &'a TransactionHeader> + Clone,
    ) -> Result<(), TransactionLogError> {
        let mut ids = BTreeSet::new();
        if headers.clone().any(|header| !ids.insert(header.id())) {
            return Err(TransactionLogError::PublicLogsAssociationMismatch);
        }
        let public_headers = headers.filter(|header| header.account_id().is_public());
        if public_headers.clone().count() != self.entries.len() {
            return Err(TransactionLogError::PublicLogsAssociationMismatch);
        }
        for ((id, logs), header) in self.entries.iter().zip(public_headers) {
            if *id != header.id() {
                return Err(TransactionLogError::PublicLogsAssociationMismatch);
            }
            if logs.commitment() != header.logs_commitment() {
                return Err(TransactionLogError::PublicLogsCommitmentMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
