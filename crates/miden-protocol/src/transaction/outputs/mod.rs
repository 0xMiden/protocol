use core::fmt::Debug;

use crate::Word;
use crate::account::AccountHeader;
use crate::asset::FungibleAsset;
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
    PrivateNoteHeader,
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
    pub account: AccountHeader,
    /// The commitment to the delta computed by the transaction kernel.
    pub account_delta_commitment: Word,
    /// Set of output notes created by the transaction.
    pub output_notes: RawOutputNotes,
    /// The fee of the transaction.
    pub fee: FungibleAsset,
    /// Defines up to which block the transaction is considered valid.
    pub expiration_block_num: BlockNumber,
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

    /// The index of the element at which the ID suffix of the faucet that issues the native asset
    /// is stored on the output stack.
    pub const NATIVE_ASSET_ID_SUFFIX_ELEMENT_IDX: usize = 8;

    /// The index of the element at which the ID prefix of the faucet that issues the native asset
    /// is stored on the output stack.
    pub const NATIVE_ASSET_ID_PREFIX_ELEMENT_IDX: usize = 9;

    /// The index of the element at which the fee amount is stored on the output stack.
    pub const FEE_AMOUNT_ELEMENT_IDX: usize = 10;

    /// The index of the item at which the expiration block height is stored on the output stack.
    pub const EXPIRATION_BLOCK_ELEMENT_IDX: usize = 11;
}

impl Serializable for TransactionOutputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account.write_into(target);
        self.account_delta_commitment.write_into(target);
        self.output_notes.write_into(target);
        self.fee.write_into(target);
        self.expiration_block_num.write_into(target);
    }
}

impl Deserializable for TransactionOutputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account = AccountHeader::read_from(source)?;
        let account_delta_commitment = Word::read_from(source)?;
        let output_notes = RawOutputNotes::read_from(source)?;
        let fee = FungibleAsset::read_from(source)?;
        let expiration_block_num = BlockNumber::read_from(source)?;

        Ok(Self {
            account,
            account_delta_commitment,
            output_notes,
            fee,
            expiration_block_num,
        })
    }
}
