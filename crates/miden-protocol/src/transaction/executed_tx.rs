use alloc::vec::Vec;

use super::{
    AccountHeader,
    AccountId,
    InputNote,
    InputNotes,
    NoteId,
    RawOutputNotes,
    TransactionArgs,
    TransactionId,
    TransactionLogs,
    TransactionOutputs,
};
use crate::Word;
use crate::account::{AccountPatch, PartialAccount};
use crate::block::{BlockHeader, BlockNumber};
use crate::transaction::TransactionInputs;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// EXECUTED TRANSACTION
// ================================================================================================

/// Describes the result of executing a transaction program for the Miden protocol.
///
/// Executed transaction serves two primary purposes:
/// - It contains a complete description of the effects of the transaction. Specifically, it
///   contains all output notes created as the result of the transaction and describes all the
///   changes made to the involved account (i.e., the account delta).
/// - It contains all the information required to re-execute and prove the transaction in a
///   stateless manner. This includes all public transaction inputs and the data the host loaded
///   lazily while executing the transaction (see [`TransactionInputs`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutedTransaction {
    id: TransactionId,
    tx_inputs: TransactionInputs,
    tx_outputs: TransactionOutputs,
    account_patch: AccountPatch,
    tx_measurements: TransactionMeasurements,
}

impl ExecutedTransaction {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [ExecutedTransaction] instantiated from the provided data.
    ///
    /// # Panics
    /// Panics if input and output account IDs are not the same.
    pub fn new(
        tx_inputs: TransactionInputs,
        tx_outputs: TransactionOutputs,
        account_patch: AccountPatch,
        tx_measurements: TransactionMeasurements,
    ) -> Self {
        // make sure account IDs are consistent across transaction inputs and outputs
        assert_eq!(tx_inputs.account().id(), tx_outputs.account().id());

        // we create the id from the content, so we cannot construct the
        // `id` value after construction `Self {..}` without moving
        let id = TransactionId::new(
            tx_inputs.account().initial_commitment(),
            tx_outputs.account().to_commitment(),
            tx_inputs.input_notes().commitment(),
            tx_outputs.output_notes().commitment(),
            tx_outputs.logs_commitment(),
        );

        Self {
            id,
            tx_inputs,
            tx_outputs,
            account_patch,
            tx_measurements,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns complete local transaction logs.
    pub fn logs(&self) -> &TransactionLogs {
        self.tx_outputs.logs()
    }

    /// Returns the transaction logs commitment included in the transaction proof.
    pub fn logs_commitment(&self) -> Word {
        self.tx_outputs.logs_commitment()
    }

    /// Returns a unique identifier of this transaction.
    pub fn id(&self) -> TransactionId {
        self.id
    }

    /// Returns the ID of the account against which this transaction was executed.
    pub fn account_id(&self) -> AccountId {
        self.initial_account().id()
    }

    /// Returns the partial state of the account before the transaction was executed.
    pub fn initial_account(&self) -> &PartialAccount {
        self.tx_inputs.account()
    }

    /// Returns the header of the account state after the transaction was executed.
    pub fn final_account(&self) -> &AccountHeader {
        self.tx_outputs.account()
    }

    /// Returns the notes consumed in this transaction.
    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        self.tx_inputs.input_notes()
    }

    /// Returns the notes created in this transaction.
    pub fn output_notes(&self) -> &RawOutputNotes {
        self.tx_outputs.output_notes()
    }

    /// Returns the block number at which the transaction will expire.
    pub fn expiration_block_num(&self) -> BlockNumber {
        self.tx_outputs.expiration_block_num()
    }

    /// Returns a reference to the transaction arguments.
    pub fn tx_args(&self) -> &TransactionArgs {
        self.tx_inputs.tx_args()
    }

    /// Returns the block header for the block against which the transaction was executed.
    pub fn block_header(&self) -> &BlockHeader {
        self.tx_inputs.block_header()
    }

    /// Returns the patch of the transaction that describes the update from the initial to the final
    /// account state.
    pub fn account_patch(&self) -> &AccountPatch {
        &self.account_patch
    }

    /// Returns a reference to the inputs for this transaction.
    pub fn tx_inputs(&self) -> &TransactionInputs {
        &self.tx_inputs
    }

    /// Returns a reference to the transaction measurements which are the cycle counts for
    /// each stage.
    pub fn measurements(&self) -> &TransactionMeasurements {
        &self.tx_measurements
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Returns individual components of this transaction.
    pub fn into_parts(
        self,
    ) -> (TransactionInputs, TransactionOutputs, AccountPatch, TransactionMeasurements) {
        (self.tx_inputs, self.tx_outputs, self.account_patch, self.tx_measurements)
    }
}

impl From<ExecutedTransaction> for TransactionInputs {
    fn from(tx: ExecutedTransaction) -> Self {
        tx.tx_inputs
    }
}

impl From<ExecutedTransaction> for TransactionMeasurements {
    fn from(tx: ExecutedTransaction) -> Self {
        let (_, _, _, tx_progress) = tx.into_parts();
        tx_progress
    }
}

// TRANSACTION MEASUREMENTS
// ================================================================================================

/// Stores the resulting number of cycles for each transaction execution stage obtained from the
/// `TransactionProgress` struct.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionMeasurements {
    pub prologue: usize,
    pub notes_processing: usize,
    pub note_execution: Vec<(NoteId, usize)>,
    pub tx_script_processing: usize,
    pub epilogue: usize,
    pub auth_procedure: usize,
}

impl TransactionMeasurements {
    /// Returns the total number of cycles spent executing the transaction.
    pub fn total_cycles(&self) -> usize {
        self.prologue + self.notes_processing + self.tx_script_processing + self.epilogue
    }
}

impl Serializable for TransactionMeasurements {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.prologue.write_into(target);
        self.notes_processing.write_into(target);
        self.note_execution.write_into(target);
        self.tx_script_processing.write_into(target);
        self.epilogue.write_into(target);
        self.auth_procedure.write_into(target);
    }
}

impl Deserializable for TransactionMeasurements {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let prologue = usize::read_from(source)?;
        let notes_processing = usize::read_from(source)?;
        let note_execution = Vec::<(NoteId, usize)>::read_from(source)?;
        let tx_script_processing = usize::read_from(source)?;
        let epilogue = usize::read_from(source)?;
        let auth_procedure = usize::read_from(source)?;

        Ok(Self {
            prologue,
            notes_processing,
            note_execution,
            tx_script_processing,
            epilogue,
            auth_procedure,
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::transaction::ExecutedTransaction;

    fn ensure_send<T: Send>(_: PhantomData<T>) {}

    /// Add assurance `ExecutedTransaction` remains `Send`
    #[allow(dead_code)]
    fn compiletime_ensure_send_for_types() {
        ensure_send::<ExecutedTransaction>(PhantomData);
    }
}
