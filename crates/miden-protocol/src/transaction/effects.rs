use super::{
    ExecutedTransaction,
    InputNote,
    InputNotes,
    RawOutputNotes,
    TransactionId,
    TransactionLogDataError,
    TransactionLogs,
};
use crate::Word;
use crate::account::AccountPatch;
use crate::block::BlockNumber;

// TRANSACTION EFFECTS
// ================================================================================================

/// The effects of an executed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEffects {
    transaction_id: TransactionId,
    initial_state_commitment: Word,
    final_state_commitment: Word,
    account_patch: AccountPatch,
    input_notes: InputNotes<InputNote>,
    output_notes: RawOutputNotes,
    ref_block_number: BlockNumber,
    ref_block_commitment: Word,
    expiration_block_num: BlockNumber,
    logs: TransactionLogs,
    log_salt: Word,
}

impl TransactionEffects {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns new [`TransactionEffects`] instantiated from the provided data.
    ///
    /// The [`TransactionId`] is computed from the account state commitments and the note
    /// commitments, so it cannot disagree with the rest of the effects.
    pub fn new(
        initial_state_commitment: Word,
        final_state_commitment: Word,
        account_patch: AccountPatch,
        input_notes: InputNotes<InputNote>,
        output_notes: RawOutputNotes,
        ref_block_number: BlockNumber,
        ref_block_commitment: Word,
        expiration_block_num: BlockNumber,
    ) -> Self {
        let transaction_id = TransactionId::new(
            initial_state_commitment,
            final_state_commitment,
            input_notes.commitment(),
            output_notes.commitment(),
            Default::default(),
        );

        Self {
            transaction_id,
            initial_state_commitment,
            final_state_commitment,
            account_patch,
            input_notes,
            output_notes,
            ref_block_number,
            ref_block_commitment,
            expiration_block_num,
            logs: TransactionLogs::default(),
            log_salt: Word::empty(),
        }
    }

    /// Attaches full local records and validates their private opening.
    pub fn with_logs(
        mut self,
        logs: TransactionLogs,
        log_salt: Word,
    ) -> Result<Self, TransactionLogDataError> {
        let commitment = logs.commitment_for_account(self.account_patch.id(), log_salt)?;
        self.transaction_id = TransactionId::new(
            self.initial_state_commitment,
            self.final_state_commitment,
            self.input_notes.commitment(),
            self.output_notes.commitment(),
            commitment,
        );
        self.logs = logs;
        self.log_salt = log_salt;
        Ok(self)
    }

    /// Returns the full local transaction log records.
    pub fn logs(&self) -> &TransactionLogs {
        &self.logs
    }

    /// Returns the private log opening.
    pub fn log_salt(&self) -> Word {
        self.log_salt
    }

    /// Returns the commitment included in the transaction ID and proof.
    pub fn logs_commitment(&self) -> Word {
        self.logs
            .commitment_for_account(self.account_patch.id(), self.log_salt)
            .expect("effects log opening is valid")
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the unique identifier of the transaction that produced these effects.
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the commitment to the account state before the transaction was executed.
    pub fn initial_state_commitment(&self) -> Word {
        self.initial_state_commitment
    }

    /// Returns the commitment to the account state after the transaction was executed.
    pub fn final_state_commitment(&self) -> Word {
        self.final_state_commitment
    }

    /// Returns the patch describing the update from the initial to the final account state.
    pub fn account_patch(&self) -> &AccountPatch {
        &self.account_patch
    }

    /// Returns the notes consumed by the transaction.
    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        &self.input_notes
    }

    /// Returns the notes created by the transaction.
    pub fn output_notes(&self) -> &RawOutputNotes {
        &self.output_notes
    }

    /// Returns the number of the block against which the transaction was executed.
    pub fn ref_block_number(&self) -> BlockNumber {
        self.ref_block_number
    }

    /// Returns the commitment to the block against which the transaction was executed.
    pub fn ref_block_commitment(&self) -> Word {
        self.ref_block_commitment
    }

    /// Returns the block number at which the transaction will expire.
    pub fn expiration_block_num(&self) -> BlockNumber {
        self.expiration_block_num
    }
}

impl From<&ExecutedTransaction> for TransactionEffects {
    fn from(tx: &ExecutedTransaction) -> Self {
        Self::new(
            tx.initial_account().initial_commitment(),
            tx.final_account().to_commitment(),
            tx.account_patch().clone(),
            tx.input_notes().clone(),
            tx.output_notes().clone(),
            tx.tx_inputs().ref_block(),
            tx.block_header().commitment(),
            tx.expiration_block_num(),
        )
        .with_logs(tx.logs().clone(), tx.tx_inputs().tx_args().log_salt())
        .expect("executed transaction has valid logs")
    }
}
