use core::fmt::Debug;

use crate::Word;
use crate::account::AccountHeader;
use crate::block::BlockNumber;
use crate::block::code_tree::CodePatch;
use crate::transaction::{TransactionKernel, TransactionLogDetails, TransactionLogs};
use crate::vm::StackOutputs;

mod notes;
pub use notes::{
    OutputNote,
    OutputNoteCollection,
    OutputNotes,
    PrivateOutputNote,
    PublicOutputNote,
    RawOutputNote,
    RawOutputNotes,
};

#[cfg(test)]
mod tests;

// TRANSACTION OUTPUTS
// ================================================================================================

/// Describes the result of executing a transaction.
///
/// # Privacy
///
/// Contains complete local transaction logs, including in debug output. Use
/// [`Self::into_parts`] to obtain the log details submitted with a proven transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionOutputs {
    /// Information related to the account's final state.
    account: AccountHeader,
    /// The commitment to the [`AccountPatch`](crate::account::AccountPatch) computed by the
    /// transaction kernel.
    account_patch_commitment: Word,
    /// Set of output notes created by the transaction.
    output_notes: RawOutputNotes,
    /// Defines up to which block the transaction is considered valid.
    expiration_block_num: BlockNumber,
    /// The logs that the transaction emitted.
    logs: TransactionLogs,
    /// The procedures the transaction adds to the code tree and the procedures it depends on.
    code_patch: CodePatch,
}

impl TransactionOutputs {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The element index starting from which the output notes commitment is stored on the output
    /// stack.
    pub const OUTPUT_NOTES_COMMITMENT_WORD_IDX: usize = 0;

    /// The element index starting from which the account update commitment word is stored on the
    /// output stack.
    pub const ACCOUNT_UPDATE_COMMITMENT_WORD_IDX: usize = 4;

    /// The element index starting from which the code patch commitment word is stored on the
    /// output stack.
    pub const CODE_PATCH_COMMITMENT_WORD_IDX: usize = 8;

    /// The element index starting from which the logs expiration commitment word is stored on the
    /// output stack.
    pub const LOGS_EXPIRATION_COMMITMENT_WORD_IDX: usize = 12;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`TransactionOutputs`] instantiated from the provided data.
    pub fn new(
        account: AccountHeader,
        account_patch_commitment: Word,
        output_notes: RawOutputNotes,
        expiration_block_num: BlockNumber,
        logs: TransactionLogs,
        code_patch: CodePatch,
    ) -> Self {
        Self {
            account,
            account_patch_commitment,
            output_notes,
            expiration_block_num,
            logs,
            code_patch,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns all transaction logs, including private transaction logs retained locally.
    pub fn logs(&self) -> &TransactionLogs {
        &self.logs
    }

    /// Returns the commitment to the local transaction logs.
    pub fn logs_commitment(&self) -> Word {
        self.logs.commitment()
    }

    /// Returns the header of the account's final state.
    pub fn account(&self) -> &AccountHeader {
        &self.account
    }

    /// Returns the commitment to the patch computed by the transaction kernel.
    pub fn account_patch_commitment(&self) -> Word {
        self.account_patch_commitment
    }

    /// Returns the set of output notes created by the transaction.
    pub fn output_notes(&self) -> &RawOutputNotes {
        &self.output_notes
    }

    /// Returns the block number at which the transaction will expire.
    pub fn expiration_block_num(&self) -> BlockNumber {
        self.expiration_block_num
    }

    /// Returns the code patch of the transaction.
    pub fn code_patch(&self) -> &CodePatch {
        &self.code_patch
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Returns the stack outputs the transaction kernel produces for these outputs.
    pub fn to_stack_outputs(&self) -> StackOutputs {
        TransactionKernel::build_output_stack(
            self.account.to_commitment(),
            self.account_patch_commitment,
            self.output_notes.commitment(),
            self.code_patch.commitment(),
            self.expiration_block_num,
            self.logs.commitment(),
        )
    }

    /// Consumes self and returns the final account header, output notes, submitted log details and
    /// code patch.
    ///
    /// The log details contain complete logs for a public native account and only their
    /// commitment for a private native account.
    pub fn into_parts(self) -> (AccountHeader, RawOutputNotes, TransactionLogDetails, CodePatch) {
        let log_details = if self.account.id().is_public() {
            TransactionLogDetails::Public(self.logs)
        } else {
            TransactionLogDetails::Private(self.logs.commitment())
        };
        (self.account, self.output_notes, log_details, self.code_patch)
    }
}
