use alloc::vec::Vec;

use crate::batch::ProvenBatch;
use crate::crypto::SequentialCommit;
use crate::transaction::{
    OrderedTransactionHeaders,
    TransactionLogDataCollection,
    TransactionLogDataError,
};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

// ORDERED BATCHES
// ================================================================================================

/// The ordered set of batches in a [`ProposedBlock`](crate::block::ProposedBlock).
///
/// This wrapper preserves batch order when converting to transaction headers and transaction log
/// data. Construction does not validate block constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedBatches(Vec<ProvenBatch>);

impl OrderedBatches {
    /// Creates a new set of ordered batches from the provided vector.
    pub fn new(batches: Vec<ProvenBatch>) -> Self {
        Self(batches)
    }

    /// Returns a reference to the underlying proven batches.
    pub fn as_slice(&self) -> &[ProvenBatch] {
        &self.0
    }

    /// Converts the transactions in batches into ordered transaction headers.
    pub fn to_transactions(&self) -> OrderedTransactionHeaders {
        OrderedTransactionHeaders::new_unchecked(
            self.0
                .iter()
                .flat_map(|batch| batch.transactions().as_slice().iter())
                .cloned()
                .collect(),
        )
    }

    /// Consumes self and converts the transactions in batches into ordered transaction headers.
    pub fn into_transactions(self) -> OrderedTransactionHeaders {
        OrderedTransactionHeaders::new_unchecked(
            self.0
                .into_iter()
                .flat_map(|batch| batch.into_transactions().into_vec().into_iter())
                .collect(),
        )
    }

    /// Consumes headers and transaction log data together, preserving batch and transaction order.
    ///
    /// # Errors
    ///
    /// Returns an error if the combined transaction log data exceeds the block resource limits.
    pub fn into_transaction_data(
        self,
    ) -> Result<(OrderedTransactionHeaders, TransactionLogDataCollection), TransactionLogDataError>
    {
        let mut headers = Vec::new();
        let mut data = Vec::new();
        for batch in self.0 {
            let (batch_headers, batch_data) = batch.into_transaction_data();
            headers.extend(batch_headers.into_vec());
            data.extend(batch_data.into_vec());
        }
        Ok((
            OrderedTransactionHeaders::new_unchecked(headers),
            TransactionLogDataCollection::new(data)?,
        ))
    }

    /// Returns the sum of created notes across all batches.
    pub fn num_created_notes(&self) -> usize {
        self.0.as_slice().iter().fold(0, |acc, batch| acc + batch.output_notes().len())
    }

    /// Consumes self and returns the underlying vector of batches.
    pub fn into_vec(self) -> Vec<ProvenBatch> {
        self.0
    }
}

impl SequentialCommit for OrderedBatches {
    type Commitment = Word;

    /// Returns batch IDs represented as a vector of field elements, in order.
    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(self.0.len() * Word::NUM_ELEMENTS);
        for batch in self.0.iter() {
            elements.extend_from_slice(batch.id().as_word().as_elements());
        }

        elements
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for OrderedBatches {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target)
    }
}

impl Deserializable for OrderedBatches {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read().map(OrderedBatches::new)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use assert_matches::assert_matches;

    use super::*;
    use crate::account::{AccountId, AccountPatch, AccountUpdateDetails};
    use crate::batch::BatchAccountUpdate;
    use crate::block::ProposedBlock;
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
    use crate::testing::dummy_execution_proof;
    use crate::transaction::{
        InputNotes,
        LogTopic,
        TransactionHeader,
        TransactionLog,
        TransactionLogData,
        TransactionLogs,
    };
    use crate::{MAX_LOGS_PER_TX, MAX_PUBLIC_LOGS_PER_BATCH, MAX_PUBLIC_LOGS_PER_BLOCK};

    #[test]
    fn transaction_data_accepts_block_log_limit() {
        let batches = batches_with_logs(MAX_PUBLIC_LOGS_PER_BLOCK / MAX_PUBLIC_LOGS_PER_BATCH);
        let expected_headers = batches.to_transactions();
        let expected_data: Vec<_> = batches
            .as_slice()
            .iter()
            .flat_map(|batch| batch.log_data().as_slice())
            .cloned()
            .collect();

        let decoded = OrderedBatches::read_from_bytes(&batches.to_bytes()).unwrap();
        let (headers, data) = decoded.into_transaction_data().unwrap();

        assert_eq!(headers, expected_headers);
        assert_eq!(data.as_slice(), expected_data);
        assert_eq!(data.as_slice().len() * MAX_LOGS_PER_TX, MAX_PUBLIC_LOGS_PER_BLOCK);
    }

    #[test]
    fn transaction_data_rejects_block_log_overflow() {
        let batches = batches_with_logs(MAX_PUBLIC_LOGS_PER_BLOCK / MAX_PUBLIC_LOGS_PER_BATCH + 1);
        let bytes = batches.to_bytes();

        assert_matches!(
            batches.into_transaction_data(),
            Err(TransactionLogDataError::AggregateBudget)
        );
        let decoded = OrderedBatches::read_from_bytes(&bytes).unwrap();
        assert_matches!(
            decoded.into_transaction_data(),
            Err(TransactionLogDataError::AggregateBudget)
        );

        // Batches are the first field in a proposed block. Reject the oversized aggregate before
        // attempting to read any remaining fields, which are deliberately absent here.
        assert_matches!(
            ProposedBlock::read_from_bytes(&bytes),
            Err(DeserializationError::InvalidValue(message))
                if message == TransactionLogDataError::AggregateBudget.to_string()
        );
    }

    /// Builds distinct, individually valid batches at the limit for public transaction logs.
    fn batches_with_logs(num_batches: usize) -> OrderedBatches {
        let account: AccountId =
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap();
        let txs_per_batch = MAX_PUBLIC_LOGS_PER_BATCH / MAX_LOGS_PER_TX;
        let mut batches = Vec::new();
        for batch_index in 0..num_batches {
            let topic = LogTopic::new([Felt::from(batch_index as u32), Felt::ONE]);
            let record = TransactionLog::new(account, topic, vec![]).unwrap();
            let entry = TransactionLogData::Public(
                TransactionLogs::new(vec![record; MAX_LOGS_PER_TX]).unwrap(),
            );
            let start = (batch_index * txs_per_batch) as u32 + 1;
            let end = start + txs_per_batch as u32;
            let headers = OrderedTransactionHeaders::new_unchecked(
                (start..end)
                    .map(|state| {
                        TransactionHeader::new(
                            account,
                            Word::from([state; 4]),
                            Word::from([state + 1; 4]),
                            InputNotes::default(),
                            vec![],
                            entry.commitment(),
                        )
                        .unwrap()
                    })
                    .collect(),
            );
            let data = TransactionLogDataCollection::new(vec![entry; txs_per_batch]).unwrap();
            let update = BatchAccountUpdate::new(
                account,
                Word::from([start; 4]),
                Word::from([end; 4]),
                AccountUpdateDetails::Public(AccountPatch::empty(account)),
            )
            .unwrap();
            batches.push(
                ProvenBatch::new(
                    Word::empty(),
                    1u32.into(),
                    vec![update],
                    InputNotes::default(),
                    vec![],
                    2u32.into(),
                    data,
                    headers,
                    dummy_execution_proof(),
                )
                .unwrap(),
            );
        }
        OrderedBatches::new(batches)
    }
}
