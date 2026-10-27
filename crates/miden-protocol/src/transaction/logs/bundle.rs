use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::{TransactionLogDetails, TransactionLogError, TransactionLogs};
use crate::Word;
use crate::batch::{OrderedBatches, ProposedBatch};
use crate::transaction::{OrderedTransactionHeaders, TransactionId};

/// Resource limits for detached public log delivery, enforced in Rust, not by the kernels.
#[derive(Debug, Clone, Copy)]
pub struct TransactionLogBundleLimits {
    pub transactions: usize,
    pub logs: usize,
    pub content_words: usize,
}

impl TransactionLogBundleLimits {
    pub const BATCH: Self = Self {
        transactions: 1024,
        logs: 4096,
        content_words: 65_536,
    };
    pub const BLOCK: Self = Self {
        transactions: 65_536,
        logs: 65_536,
        content_words: 524_288,
    };

    /// Checks aggregate counts, including private transactions and transactions with no logs.
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
            return Err(TransactionLogError::BundleLimitExceeded);
        }
        Ok(())
    }
}

/// Complete public logs delivered separately from a batch or block.
///
/// There is exactly one entry per public native account transaction, including empty log lists,
/// in transaction order. Private transactions have no entries, even when they call public foreign
/// accounts. The transaction commitment binds the entire header sequence, including private
/// transactions. Duplicate logs within a transaction are preserved.
///
/// Validation establishes agreement with the supplied headers, not their authenticity. Consumers
/// must authenticate the enclosing batch/block separately. Discarding this bundle does not change
/// a block or its validity; it only removes the ability to serve its public logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicTransactionLogBundle {
    transactions_commitment: Word,
    entries: Vec<(TransactionId, TransactionLogs)>,
}

impl PublicTransactionLogBundle {
    /// Builds a complete bundle matching the supplied headers, within block delivery limits.
    pub fn new(
        entries: Vec<(TransactionId, TransactionLogs)>,
        headers: &OrderedTransactionHeaders,
    ) -> Result<Self, TransactionLogError> {
        TransactionLogBundleLimits::BLOCK.check(headers.as_slice().len(), 0, 0)?;
        let bundle = Self {
            transactions_commitment: headers.commitment(),
            entries,
        };
        bundle.validate_for_block(headers)?;
        Ok(bundle)
    }

    /// Extracts public logs before proving consumes the proposal's full transactions.
    pub fn from_batch(batch: &ProposedBatch) -> Result<Self, TransactionLogError> {
        TransactionLogBundleLimits::BATCH.check(batch.transactions().len(), 0, 0)?;
        let mut entries = Vec::new();
        let (mut num_logs, mut num_words) = (0, 0);
        for tx in batch.transactions() {
            if let TransactionLogDetails::Public(logs) = tx.log_details() {
                num_logs += logs.num_logs();
                num_words += logs.num_content_words();
                TransactionLogBundleLimits::BATCH.check(
                    batch.transactions().len(),
                    num_logs,
                    num_words,
                )?;
                entries.push((tx.id(), logs.clone()));
            }
        }
        Self::new(entries, &batch.transaction_headers())
    }

    /// Combines one complete bundle per batch, preserving the block's batch/transaction order.
    ///
    /// Bundles for private-only batches are required too, so omission or reordering is detected.
    pub fn from_batches(
        batches: &OrderedBatches,
        bundles: Vec<Self>,
    ) -> Result<Self, TransactionLogError> {
        if bundles.len() != batches.as_slice().len() {
            return Err(TransactionLogError::BundleAssociationMismatch);
        }
        let mut entries = Vec::new();
        let (mut num_transactions, mut num_logs, mut num_words) = (0, 0, 0);
        for (batch, bundle) in batches.as_slice().iter().zip(bundles) {
            bundle.validate_for_batch(batch.transactions())?;
            num_transactions += batch.transactions().as_slice().len();
            for (_, logs) in &bundle.entries {
                num_logs += logs.num_logs();
                num_words += logs.num_content_words();
            }
            TransactionLogBundleLimits::BLOCK.check(num_transactions, num_logs, num_words)?;
            entries.extend(bundle.entries);
        }
        Self::new(entries, &batches.to_transactions())
    }

    /// Commitment to all transaction headers, including those with private or empty logs.
    pub fn transactions_commitment(&self) -> Word {
        self.transactions_commitment
    }

    /// Public log lists in transaction order, keyed by transaction ID.
    pub fn entries(&self) -> &[(TransactionId, TransactionLogs)] {
        &self.entries
    }

    /// Checks completeness, associations, visibility, commitments and batch delivery limits.
    pub fn validate_for_batch(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogError> {
        self.validate(headers, TransactionLogBundleLimits::BATCH)
    }

    /// Checks completeness, associations, visibility, commitments and block delivery limits.
    pub fn validate_for_block(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogError> {
        self.validate(headers, TransactionLogBundleLimits::BLOCK)
    }

    fn validate(
        &self,
        headers: &OrderedTransactionHeaders,
        limits: TransactionLogBundleLimits,
    ) -> Result<(), TransactionLogError> {
        limits.check(headers.as_slice().len().max(self.entries.len()), 0, 0)?;
        let (mut num_logs, mut num_words) = (0, 0);
        for (_, logs) in &self.entries {
            num_logs += logs.num_logs();
            num_words += logs.num_content_words();
            limits.check(headers.as_slice().len(), num_logs, num_words)?;
        }
        if self.transactions_commitment != headers.commitment() {
            return Err(TransactionLogError::BundleCommitmentMismatch);
        }
        let mut ids = BTreeSet::new();
        let mut entries = self.entries.iter();
        for header in headers.as_slice() {
            if !ids.insert(header.id()) {
                return Err(TransactionLogError::BundleAssociationMismatch);
            }
            if header.account_id().is_public() {
                let Some((id, logs)) = entries.next() else {
                    return Err(TransactionLogError::BundleAssociationMismatch);
                };
                if *id != header.id() {
                    return Err(TransactionLogError::BundleAssociationMismatch);
                }
                if logs.commitment() != header.logs_commitment() {
                    return Err(TransactionLogError::BundleCommitmentMismatch);
                }
            }
        }
        if entries.next().is_some() {
            return Err(TransactionLogError::BundleAssociationMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
