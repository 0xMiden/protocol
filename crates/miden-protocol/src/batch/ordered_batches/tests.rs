use alloc::string::ToString;
use alloc::vec::Vec;

use assert_matches::assert_matches;

use crate::account::{AccountId, AccountPatch, AccountUpdateDetails};
use crate::batch::{BatchAccountUpdate, OrderedBatches, ProvenBatch};
use crate::block::ProposedBlock;
use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use crate::testing::dummy_execution_proof;
use crate::transaction::{
    InputNotes,
    LogTopic,
    OrderedTransactionHeaders,
    TransactionHeader,
    TransactionLog,
    TransactionLogData,
    TransactionLogDataCollection,
    TransactionLogError,
    TransactionLogs,
};
use crate::utils::serde::{Deserializable, DeserializationError, Serializable};
use crate::{Felt, MAX_LOGS_PER_TX, MAX_PUBLIC_LOGS_PER_BATCH, MAX_PUBLIC_LOGS_PER_BLOCK, Word};

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

    assert_matches!(batches.into_transaction_data(), Err(TransactionLogError::AggregateBudget));
    let decoded = OrderedBatches::read_from_bytes(&bytes).unwrap();
    assert_matches!(decoded.into_transaction_data(), Err(TransactionLogError::AggregateBudget));

    // Batches are the first field in a proposed block. Reject the oversized aggregate before
    // attempting to read any remaining fields, which are deliberately absent here.
    assert_matches!(
        ProposedBlock::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(message))
            if message == TransactionLogError::AggregateBudget.to_string()
    );
}

/// Builds distinct, individually valid batches at the limit for public transaction logs.
fn batches_with_logs(num_batches: usize) -> OrderedBatches {
    let account: AccountId = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap();
    let txs_per_batch = MAX_PUBLIC_LOGS_PER_BATCH / MAX_LOGS_PER_TX;
    let mut batches = Vec::new();
    for batch_index in 0..num_batches {
        let topic = LogTopic::new([Felt::from(batch_index as u32), Felt::ONE]);
        let transaction_log = TransactionLog::new(account, topic, vec![]).unwrap();
        let entry = TransactionLogData::Public(
            TransactionLogs::new(vec![transaction_log; MAX_LOGS_PER_TX]).unwrap(),
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
