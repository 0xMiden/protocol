use super::{ExecutedTransaction, TransactionInputs};
use crate::account::AccountHeader;
use crate::block::BlockNumber;
use crate::block::code_tree::CodePatch;

// TRANSACTION WITNESS
// ================================================================================================

/// The data required to prove a transaction.
///
/// The witness contains the inputs to re-execute the transaction and the outputs that the
/// re-execution cannot reconstruct by itself. A prover rebuilds the remaining outputs from the
/// re-execution and checks all outputs against the stack outputs before it uses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionWitness {
    tx_inputs: TransactionInputs,
    final_account: AccountHeader,
    expiration_block_num: BlockNumber,
    code_patch: CodePatch,
}

impl TransactionWitness {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`TransactionWitness`] instantiated from the provided parts.
    ///
    /// This does not check that the final account, expiration block number and code patch are the
    /// result of executing the inputs. A prover must check this before it uses them.
    pub fn new_unchecked(
        tx_inputs: TransactionInputs,
        final_account: AccountHeader,
        expiration_block_num: BlockNumber,
        code_patch: CodePatch,
    ) -> Self {
        Self {
            tx_inputs,
            final_account,
            expiration_block_num,
            code_patch,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the inputs required to re-execute the transaction.
    pub fn tx_inputs(&self) -> &TransactionInputs {
        &self.tx_inputs
    }

    /// Returns the header of the account after the transaction is executed.
    pub fn final_account(&self) -> &AccountHeader {
        &self.final_account
    }

    /// Returns the block number at which the transaction expires.
    pub fn expiration_block_num(&self) -> BlockNumber {
        self.expiration_block_num
    }

    /// Returns the code patch of the transaction.
    pub fn code_patch(&self) -> &CodePatch {
        &self.code_patch
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the transaction inputs, the final account header, the expiration
    /// block number and the code patch.
    pub fn into_parts(self) -> (TransactionInputs, AccountHeader, BlockNumber, CodePatch) {
        (self.tx_inputs, self.final_account, self.expiration_block_num, self.code_patch)
    }
}

impl From<ExecutedTransaction> for TransactionWitness {
    fn from(tx: ExecutedTransaction) -> Self {
        let (tx_inputs, tx_outputs, ..) = tx.into_parts();
        let expiration_block_num = tx_outputs.expiration_block_num();
        let (final_account, _, _, code_patch) = tx_outputs.into_parts();
        Self::new_unchecked(tx_inputs, final_account, expiration_block_num, code_patch)
    }
}
