use core::fmt::Debug;

use crate::Word;
use crate::account::AccountHeader;
use crate::block::BlockNumber;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

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

    /// The index of the item at which the expiration block height is stored on the output stack.
    pub const EXPIRATION_BLOCK_ELEMENT_IDX: usize = 8;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`TransactionOutputs`] instantiated from the provided data.
    pub fn new(
        account: AccountHeader,
        account_patch_commitment: Word,
        output_notes: RawOutputNotes,
        expiration_block_num: BlockNumber,
    ) -> Self {
        Self {
            account,
            account_patch_commitment,
            output_notes,
            expiration_block_num,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

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

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the individual parts (that are non-Copy).
    pub fn into_parts(self) -> (AccountHeader, RawOutputNotes) {
        (self.account, self.output_notes)
    }
}

impl Serializable for TransactionOutputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account.write_into(target);
        self.account_patch_commitment.write_into(target);
        self.output_notes.write_into(target);
        self.expiration_block_num.write_into(target);
    }
}

impl Deserializable for TransactionOutputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account = AccountHeader::read_from(source)?;
        let account_patch_commitment = Word::read_from(source)?;
        let output_notes = RawOutputNotes::read_from(source)?;
        let expiration_block_num = BlockNumber::read_from(source)?;

        Ok(Self {
            account,
            account_patch_commitment,
            output_notes,
            expiration_block_num,
        })
    }
}
