use alloc::vec::Vec;

use super::{TransactionLogDetails, TransactionLogError, TransactionLogs};
use crate::batch::ProposedBatch;
use crate::transaction::{TransactionHeader, TransactionId};

/// Complete public log collections in native transaction order.
///
/// Each public native-account transaction has one entry, including empty collections. Private
/// transactions have none, even when they call public foreign accounts. Duplicate logs are
/// retained. The enclosing batch/block headers already commit to these payloads; there is no
/// separate root. Validation checks consistency with headers, not their authenticity. Owners
/// must revalidate the association with their own headers and enforce transaction uniqueness.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublicTransactionLogs {
    entries: Vec<(TransactionId, TransactionLogs)>,
}

impl PublicTransactionLogs {
    /// Maximum number of public log content words across all transaction entries in a batch or
    /// block.
    pub const MAX_NUM_WORDS: usize = 512 * TransactionLogs::MAX_NUM_WORDS;

    /// Associates complete public logs with ordered transaction headers.
    ///
    /// # Errors
    /// Rejects missing, extra or reordered associations, private entries, and payloads
    /// that do not match the header's log commitment, or more than [`Self::MAX_NUM_WORDS`] content
    /// words.
    pub fn new<'a>(
        entries: Vec<(TransactionId, TransactionLogs)>,
        headers: impl Iterator<Item = &'a TransactionHeader> + Clone,
    ) -> Result<Self, TransactionLogError> {
        let logs = Self { entries };
        logs.validate(headers)?;
        Ok(logs)
    }

    /// Copies public logs from the full transactions of a validated proposal.
    ///
    /// # Errors
    /// Rejects more than [`Self::MAX_NUM_WORDS`] public log content words or inconsistent
    /// transaction headers.
    pub fn from_batch(batch: &ProposedBatch) -> Result<Self, TransactionLogError> {
        let entries = batch
            .transactions()
            .iter()
            .filter_map(|tx| match tx.log_details() {
                TransactionLogDetails::Public(logs) => Some((tx.id(), logs.clone())),
                TransactionLogDetails::Private(_) => None,
            })
            .collect();
        Self::new(entries, batch.transaction_headers().as_slice().iter())
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

    /// Checks completeness, visibility, association, commitments and the public-content-word limit.
    ///
    /// # Errors
    /// Rejects an invalid association, payload hash, or more than [`Self::MAX_NUM_WORDS`] content
    /// words.
    pub(crate) fn validate<'a>(
        &self,
        headers: impl Iterator<Item = &'a TransactionHeader> + Clone,
    ) -> Result<(), TransactionLogError> {
        Self::check_num_content_words(self.entries.iter().map(|(_, logs)| logs))?;
        self.validate_entries(headers)
    }

    /// Checks the combined content word count before proving or concatenating collections.
    pub(crate) fn check_num_content_words<'a>(
        logs: impl IntoIterator<Item = &'a TransactionLogs>,
    ) -> Result<(), TransactionLogError> {
        let mut count = 0usize;
        for logs in logs {
            count = count
                .checked_add(logs.num_content_words())
                .ok_or(TransactionLogError::PublicLogsLimitExceeded)?;
            if count > Self::MAX_NUM_WORDS {
                return Err(TransactionLogError::PublicLogsLimitExceeded);
            }
        }
        Ok(())
    }

    fn validate_entries<'a>(
        &self,
        headers: impl Iterator<Item = &'a TransactionHeader> + Clone,
    ) -> Result<(), TransactionLogError> {
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
