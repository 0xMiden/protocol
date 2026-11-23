use miden_protobuf::unwrap_infallible;
use miden_protocol::transaction::TransactionOutputs;
pub use proto::transaction::transaction_measurements::DecodedNoteExecution as NoteExecution;

use crate::decoded::VerificationError;
use crate::{BuildUnchecked, Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for NoteExecution {
    type Verified = (miden_protocol::note::NoteId, u32);
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((unwrap_infallible(self.note_id.verify()), self.cycles))
    }
}

pub use proto::transaction::DecodedTransactionMeasurements as TransactionMeasurements;

impl Verify for TransactionMeasurements {
    type Verified = miden_protocol::transaction::TransactionMeasurements;
    type Error = miden_protocol::errors::TransactionMeasurementsError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Self::Verified::builder()
            .prologue(self.prologue)
            .notes_processing(self.notes_processing)
            .note_execution(self.note_execution.verify_infallible())
            .tx_script_processing(self.tx_script_processing)
            .epilogue(self.epilogue)
            .auth_procedure(self.auth_procedure)
            .build()
    }
}

pub use proto::transaction::DecodedExecutedTransactionV1 as ExecutedTransactionV1;

/// Builds the inputs under the same conditions as [`super::TransactionInputsV1`]. The outputs, the
/// account patch and the measurements are not checked to be the result of executing the inputs, so
/// the message must come from a trusted source.
impl BuildUnchecked for ExecutedTransactionV1 {
    type Output = miden_protocol::transaction::ExecutedTransaction;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let account_patch = self.account_patch.verify()?;
        let tx_outputs = TransactionOutputs::new(
            self.final_account.verify()?,
            account_patch.to_commitment(),
            self.output_notes.verify()?,
            unwrap_infallible(self.expiration_block_num.verify()),
            self.logs.verify()?,
            self.code_patch.verify()?,
        );
        Ok(Self::Output::new(
            self.tx_inputs.build_unchecked()?,
            tx_outputs,
            account_patch,
            self.measurements.verify()?,
        )?)
    }
}

pub use proto::transaction::DecodedExecutedTransaction as ExecutedTransaction;

/// Dispatches the decoded version.
impl BuildUnchecked for ExecutedTransaction {
    type Output = miden_protocol::transaction::ExecutedTransaction;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        let proto::transaction::executed_transaction::DecodedVersion::V1(transaction) =
            self.version;
        transaction.build_unchecked()
    }
}
