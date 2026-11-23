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
use crate::account::{AccountPatch, PartialAccount};
use crate::block::code_tree::CodePatch;
use crate::block::{BlockHeader, BlockNumber};
use crate::errors::{ExecutedTransactionError, TransactionMeasurementsError};
use crate::transaction::TransactionInputs;
use crate::{MAX_TX_EXECUTION_CYCLES, Word};

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
    /// # Errors
    ///
    /// Returns an error if:
    /// - the account IDs of the transaction inputs and outputs are not the same.
    /// - the account patch is for a different account.
    /// - the account patch does not match the commitment in the transaction outputs.
    pub fn new(
        tx_inputs: TransactionInputs,
        tx_outputs: TransactionOutputs,
        account_patch: AccountPatch,
        tx_measurements: TransactionMeasurements,
    ) -> Result<Self, ExecutedTransactionError> {
        let input_id = tx_inputs.account().id();
        let output_id = tx_outputs.account().id();
        if input_id != output_id {
            return Err(ExecutedTransactionError::InconsistentAccountId { input_id, output_id });
        }

        // The commitment to an empty patch does not bind the account ID, so it is checked
        // separately.
        if account_patch.id() != input_id {
            return Err(ExecutedTransactionError::InconsistentAccountPatchId {
                patch_id: account_patch.id(),
                account_id: input_id,
            });
        }

        let output_commitment = tx_outputs.account_patch_commitment();
        let patch_commitment = account_patch.to_commitment();
        if output_commitment != patch_commitment {
            return Err(ExecutedTransactionError::InconsistentAccountPatchCommitment {
                output_commitment,
                patch_commitment,
            });
        }

        // we create the id from the content, so we cannot construct the
        // `id` value after construction `Self {..}` without moving
        let id = TransactionId::new(
            tx_inputs.account().initial_commitment(),
            tx_outputs.account().to_commitment(),
            tx_inputs.input_notes().commitment(),
            tx_outputs.output_notes().commitment(),
            tx_outputs.logs_commitment(),
            tx_outputs.code_patch().commitment(),
        );

        Ok(Self {
            id,
            tx_inputs,
            tx_outputs,
            account_patch,
            tx_measurements,
        })
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

    /// Returns the code patch of this transaction.
    pub fn code_patch(&self) -> &CodePatch {
        self.tx_outputs.code_patch()
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
    prologue: u32,
    notes_processing: u32,
    note_execution: Vec<(NoteId, u32)>,
    tx_script_processing: u32,
    epilogue: u32,
    auth_procedure: u32,
}

#[bon::bon]
impl TransactionMeasurements {
    /// Returns new [`TransactionMeasurements`] instantiated from the provided cycle counts.
    ///
    /// # Errors
    ///
    /// Returns an error if the total number of cycles exceeds [`MAX_TX_EXECUTION_CYCLES`].
    #[builder]
    pub fn new(
        prologue: u32,
        notes_processing: u32,
        note_execution: Vec<(NoteId, u32)>,
        tx_script_processing: u32,
        epilogue: u32,
        auth_procedure: u32,
    ) -> Result<Self, TransactionMeasurementsError> {
        let total_cycles = [prologue, notes_processing, tx_script_processing, epilogue]
            .into_iter()
            .map(u64::from)
            .sum::<u64>();
        if total_cycles > u64::from(MAX_TX_EXECUTION_CYCLES) {
            return Err(TransactionMeasurementsError::TotalCyclesExceedsMax(total_cycles));
        }

        Ok(Self {
            prologue,
            notes_processing,
            note_execution,
            tx_script_processing,
            epilogue,
            auth_procedure,
        })
    }

    /// Returns the number of cycles spent in the prologue.
    pub fn prologue(&self) -> u32 {
        self.prologue
    }

    /// Returns the number of cycles spent processing all input notes.
    pub fn notes_processing(&self) -> u32 {
        self.notes_processing
    }

    /// Returns the number of cycles spent executing each input note.
    pub fn note_execution(&self) -> &[(NoteId, u32)] {
        &self.note_execution
    }

    /// Returns the number of cycles spent processing the transaction script.
    pub fn tx_script_processing(&self) -> u32 {
        self.tx_script_processing
    }

    /// Returns the number of cycles spent in the epilogue, including the authentication procedure.
    pub fn epilogue(&self) -> u32 {
        self.epilogue
    }

    /// Returns the number of cycles spent in the authentication procedure.
    pub fn auth_procedure(&self) -> u32 {
        self.auth_procedure
    }

    /// Returns the total number of cycles spent executing the transaction.
    pub fn total_cycles(&self) -> u32 {
        // The constructor guarantees that the sum does not overflow.
        self.prologue + self.notes_processing + self.tx_script_processing + self.epilogue
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::marker::PhantomData;

    use assert_matches::assert_matches;

    use super::*;
    use crate::Felt;
    use crate::account::{AccountCodePatch, AccountStoragePatch, AccountVaultPatch};
    use crate::testing::account_id::{
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    };
    use crate::transaction::inputs::tests::empty_tx_inputs;

    /// The account of [`empty_tx_inputs`].
    const NATIVE_ACCOUNT: u128 = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    const OTHER_ACCOUNT: u128 = ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2;

    fn ensure_send<T: Send>(_: PhantomData<T>) {}

    /// Add assurance `ExecutedTransaction` remains `Send`
    #[allow(dead_code)]
    fn compiletime_ensure_send_for_types() {
        ensure_send::<ExecutedTransaction>(PhantomData);
    }

    #[rstest::rstest]
    #[case::output_account_id(
        OTHER_ACCOUNT,
        NATIVE_ACCOUNT,
        None,
        |error: &_| matches!(error, ExecutedTransactionError::InconsistentAccountId { .. })
    )]
    #[case::patch_account_id(
        NATIVE_ACCOUNT,
        OTHER_ACCOUNT,
        None,
        |error: &_| matches!(error, ExecutedTransactionError::InconsistentAccountPatchId { .. })
    )]
    #[case::patch_commitment(
        NATIVE_ACCOUNT,
        NATIVE_ACCOUNT,
        Some(Word::from([1_u32, 2, 3, 4])),
        |error: &_| matches!(error, ExecutedTransactionError::InconsistentAccountPatchCommitment { .. })
    )]
    fn executed_transaction_rejects_inconsistent_parts(
        #[case] output_id: u128,
        #[case] patch_id: u128,
        #[case] output_patch_commitment: Option<Word>,
        #[case] is_expected: fn(&ExecutedTransactionError) -> bool,
    ) -> anyhow::Result<()> {
        let account_patch = AccountPatch::new(
            patch_id.try_into()?,
            AccountStoragePatch::default(),
            AccountVaultPatch::default(),
            AccountCodePatch::default(),
            None,
        )?;
        let tx_outputs = TransactionOutputs::new(
            AccountHeader::new(
                output_id.try_into()?,
                Felt::ONE,
                Word::empty(),
                Word::empty(),
                Word::empty(),
            ),
            output_patch_commitment.unwrap_or_else(|| account_patch.to_commitment()),
            RawOutputNotes::new(vec![])?,
            BlockNumber::from(1_u32),
            TransactionLogs::default(),
            CodePatch::default(),
        );
        let measurements = TransactionMeasurements::builder()
            .prologue(0)
            .notes_processing(0)
            .note_execution(vec![])
            .tx_script_processing(0)
            .epilogue(0)
            .auth_procedure(0)
            .build()?;

        let error =
            ExecutedTransaction::new(empty_tx_inputs()?, tx_outputs, account_patch, measurements)
                .unwrap_err();
        assert!(is_expected(&error), "unexpected error: {error}");

        Ok(())
    }

    /// Returns the total cycles of measurements with the provided prologue and epilogue cycles.
    fn build_total_cycles(
        prologue: u32,
        epilogue: u32,
    ) -> Result<u32, TransactionMeasurementsError> {
        TransactionMeasurements::builder()
            .prologue(prologue)
            .notes_processing(0)
            .note_execution(vec![])
            .tx_script_processing(0)
            .epilogue(epilogue)
            .auth_procedure(0)
            .build()
            .map(|measurements| measurements.total_cycles())
    }

    #[test]
    fn transaction_measurements_accept_max_total_cycles() -> anyhow::Result<()> {
        assert_eq!(build_total_cycles(MAX_TX_EXECUTION_CYCLES - 1, 1)?, MAX_TX_EXECUTION_CYCLES);

        Ok(())
    }

    #[rstest::rstest]
    #[case::above_max(MAX_TX_EXECUTION_CYCLES, 1)]
    #[case::above_u32(u32::MAX, u32::MAX)]
    fn transaction_measurements_reject_total_cycles_above_max(
        #[case] prologue: u32,
        #[case] epilogue: u32,
    ) {
        assert_matches!(
            build_total_cycles(prologue, epilogue),
            Err(TransactionMeasurementsError::TotalCyclesExceedsMax(total_cycles))
                if total_cycles == u64::from(prologue) + u64::from(epilogue)
        );
    }
}
