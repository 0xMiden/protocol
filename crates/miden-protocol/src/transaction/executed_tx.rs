use alloc::vec::Vec;

use super::{
    AccountDelta,
    AccountHeader,
    AccountId,
    AdviceInputs,
    InputNote,
    InputNotes,
    NoteId,
    OutputNotes,
    TransactionArgs,
    TransactionId,
    TransactionOutputs,
};
use crate::account::PartialAccount;
use crate::asset::FungibleAsset;
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
///   stateless manner. This includes all public transaction inputs, but also all nondeterministic
///   inputs that the host provided to Miden VM while executing the transaction (i.e., advice
///   witness).
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutedTransaction {
    id: TransactionId,
    tx_inputs: TransactionInputs,
    tx_outputs: TransactionOutputs,
    account_delta: AccountDelta,
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
        account_delta: AccountDelta,
        tx_measurements: TransactionMeasurements,
    ) -> Self {
        // make sure account IDs are consistent across transaction inputs and outputs
        assert_eq!(tx_inputs.account().id(), tx_outputs.account.id());

        // we create the id from the content, so we cannot construct the
        // `id` value after construction `Self {..}` without moving
        let id = TransactionId::new(
            tx_inputs.account().initial_commitment(),
            tx_outputs.account.commitment(),
            tx_inputs.input_notes().commitment(),
            tx_outputs.output_notes.commitment(),
        );

        Self {
            id,
            tx_inputs,
            tx_outputs,
            account_delta,
            tx_measurements,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

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
        &self.tx_outputs.account
    }

    /// Returns the notes consumed in this transaction.
    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        self.tx_inputs.input_notes()
    }

    /// Returns the notes created in this transaction.
    pub fn output_notes(&self) -> &OutputNotes {
        &self.tx_outputs.output_notes
    }

    /// Returns the fee of the transaction.
    pub fn fee(&self) -> FungibleAsset {
        self.tx_outputs.fee
    }

    /// Returns the block number at which the transaction will expire.
    pub fn expiration_block_num(&self) -> BlockNumber {
        self.tx_outputs.expiration_block_num
    }

    /// Returns a reference to the transaction arguments.
    pub fn tx_args(&self) -> &TransactionArgs {
        self.tx_inputs.tx_args()
    }

    /// Returns the block header for the block against which the transaction was executed.
    pub fn block_header(&self) -> &BlockHeader {
        self.tx_inputs.block_header()
    }

    /// Returns a description of changes between the initial and final account states.
    pub fn account_delta(&self) -> &AccountDelta {
        &self.account_delta
    }

    /// Returns a reference to the inputs for this transaction.
    pub fn tx_inputs(&self) -> &TransactionInputs {
        &self.tx_inputs
    }

    /// Returns all the data requested by the VM from the advice provider while executing the
    /// transaction program.
    pub fn advice_witness(&self) -> &AdviceInputs {
        self.tx_inputs.advice_inputs()
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
    ) -> (TransactionInputs, TransactionOutputs, AccountDelta, TransactionMeasurements) {
        (self.tx_inputs, self.tx_outputs, self.account_delta, self.tx_measurements)
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

impl Serializable for ExecutedTransaction {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.tx_inputs.write_into(target);
        self.tx_outputs.write_into(target);
        self.account_delta.write_into(target);
        self.tx_measurements.write_into(target);
    }
}

impl Deserializable for ExecutedTransaction {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tx_inputs = TransactionInputs::read_from(source)?;
        let tx_outputs = TransactionOutputs::read_from(source)?;
        let account_delta = AccountDelta::read_from(source)?;
        let tx_measurements = TransactionMeasurements::read_from(source)?;

        Ok(Self::new(tx_inputs, tx_outputs, account_delta, tx_measurements))
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
    /// The number of cycles the epilogue took to execute after compute_fee determined the cycle
    /// count.
    ///
    /// This is used to get the total number of cycles the transaction takes for use in
    /// compute_fee itself.
    pub after_tx_cycles_obtained: usize,
}

impl TransactionMeasurements {
    /// Returns the total number of cycles spent executing the transaction.
    pub fn total_cycles(&self) -> usize {
        self.prologue + self.notes_processing + self.tx_script_processing + self.epilogue
    }

    /// Returns the trace length of the transaction which is the next power of 2 of the total cycles
    /// spent executing the transaction.
    pub fn trace_length(&self) -> usize {
        let total_cycles = self.total_cycles();
        total_cycles.next_power_of_two()
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
        self.after_tx_cycles_obtained.write_into(target);
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
        let after_tx_cycles_obtained = usize::read_from(source)?;

        Ok(Self {
            prologue,
            notes_processing,
            note_execution,
            tx_script_processing,
            epilogue,
            auth_procedure,
            after_tx_cycles_obtained,
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
