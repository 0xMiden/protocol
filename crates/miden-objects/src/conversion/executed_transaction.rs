use miden_protocol::transaction::{ExecutedTransaction, TransactionMeasurements};

use crate::proto;

// TRANSACTION MEASUREMENTS
// ================================================================================================

impl From<&TransactionMeasurements> for proto::transaction::TransactionMeasurements {
    fn from(measurements: &TransactionMeasurements) -> Self {
        use proto::transaction::transaction_measurements::NoteExecution;

        Self {
            prologue: measurements.prologue(),
            notes_processing: measurements.notes_processing(),
            note_execution: measurements
                .note_execution()
                .iter()
                .map(|(note_id, cycles)| NoteExecution {
                    note_id: Some(note_id.into()),
                    cycles: *cycles,
                })
                .collect(),
            tx_script_processing: measurements.tx_script_processing(),
            epilogue: measurements.epilogue(),
            auth_procedure: measurements.auth_procedure(),
        }
    }
}

// EXECUTED TRANSACTION
// ================================================================================================

impl From<&ExecutedTransaction> for proto::transaction::ExecutedTransactionV1 {
    fn from(transaction: &ExecutedTransaction) -> Self {
        Self {
            tx_inputs: Some(transaction.tx_inputs().into()),
            final_account: Some(transaction.final_account().into()),
            output_notes: Some(transaction.output_notes().into()),
            expiration_block_num: Some(transaction.expiration_block_num().into()),
            logs: Some(transaction.logs().into()),
            code_patch: Some(transaction.code_patch().into()),
            account_patch: Some(transaction.account_patch().into()),
            measurements: Some(transaction.measurements().into()),
        }
    }
}

impl From<&ExecutedTransaction> for proto::transaction::ExecutedTransaction {
    fn from(transaction: &ExecutedTransaction) -> Self {
        use proto::transaction::executed_transaction::Version;

        Self {
            version: Some(Version::V1(transaction.into())),
        }
    }
}

impl From<ExecutedTransaction> for proto::transaction::ExecutedTransaction {
    fn from(transaction: ExecutedTransaction) -> Self {
        Self::from(&transaction)
    }
}
