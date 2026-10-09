use super::{ExecutedTransaction, TransactionInputs};
use crate::account::AccountHeader;
use crate::block::BlockNumber;

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
}

impl TransactionWitness {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`TransactionWitness`] instantiated from the provided parts.
    ///
    /// This does not check that the final account and expiration block number are the result of
    /// executing the inputs. A prover must check this before it uses them.
    pub fn new_unchecked(
        tx_inputs: TransactionInputs,
        final_account: AccountHeader,
        expiration_block_num: BlockNumber,
    ) -> Self {
        Self {
            tx_inputs,
            final_account,
            expiration_block_num,
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

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the transaction inputs, the final account header and the
    /// expiration block number.
    pub fn into_parts(self) -> (TransactionInputs, AccountHeader, BlockNumber) {
        (self.tx_inputs, self.final_account, self.expiration_block_num)
    }
}

impl From<ExecutedTransaction> for TransactionWitness {
    fn from(tx: ExecutedTransaction) -> Self {
        let (tx_inputs, tx_outputs, ..) = tx.into_parts();
        let expiration_block_num = tx_outputs.expiration_block_num();
        let (final_account, _) = tx_outputs.into_parts();
        Self::new_unchecked(tx_inputs, final_account, expiration_block_num)
    }
}

// SERIALIZATION
// ================================================================================================
