use alloc::vec::Vec;

use crate::account::AccountDelta;
use crate::crypto::SequentialCommit;
use crate::transaction::{InputNote, InputNotes, RawOutputNotes};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

/// The summary of the changes that result from executing a transaction.
///
/// These are the account delta and the consumed and created notes. Because this data is intended to
/// be used for signing a transaction a user-defined salt is included as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSummary {
    account_delta: AccountDelta,
    input_notes: InputNotes<InputNote>,
    output_notes: RawOutputNotes,
    block_commitment: Word,
    ref_params: Word,
    salt: Word,
}

impl TransactionSummary {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionSummary`] from the provided parts.
    ///
    /// `block_commitment` is the commitment to the transaction's reference block, and `ref_params`
    /// is `[0, 0, expiration_delta, ref_block_num]`. Both are bound into the signed summary so that
    /// a delegated prover cannot alter the reference block or the transaction expiration without
    /// invalidating the signature.
    pub fn new(
        account_delta: AccountDelta,
        input_notes: InputNotes<InputNote>,
        output_notes: RawOutputNotes,
        block_commitment: Word,
        ref_params: Word,
        salt: Word,
    ) -> Self {
        Self {
            account_delta,
            input_notes,
            output_notes,
            block_commitment,
            ref_params,
            salt,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the account delta of this transaction summary.
    pub fn account_delta(&self) -> &AccountDelta {
        &self.account_delta
    }

    /// Returns the input notes of this transaction summary.
    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        &self.input_notes
    }

    /// Returns the output notes of this transaction summary.
    pub fn output_notes(&self) -> &RawOutputNotes {
        &self.output_notes
    }

    /// Returns the reference block commitment of this transaction summary.
    pub fn block_commitment(&self) -> Word {
        self.block_commitment
    }

    /// Returns the reference parameters `[0, 0, expiration_delta, ref_block_num]` of this
    /// transaction summary.
    pub fn ref_params(&self) -> Word {
        self.ref_params
    }

    /// Returns the salt of this transaction summary.
    pub fn salt(&self) -> Word {
        self.salt
    }

    /// Computes the commitment to the [`TransactionSummary`].
    ///
    /// This can be used to sign the transaction.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl SequentialCommit for TransactionSummary {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(24);
        elements.extend_from_slice(self.account_delta.to_commitment().as_elements());
        elements.extend_from_slice(self.input_notes.commitment().as_elements());
        elements.extend_from_slice(self.output_notes.commitment().as_elements());
        elements.extend_from_slice(self.block_commitment.as_elements());
        elements.extend_from_slice(self.ref_params.as_elements());
        elements.extend_from_slice(self.salt.as_elements());
        elements
    }
}

impl Serializable for TransactionSummary {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_delta.write_into(target);
        self.input_notes.write_into(target);
        self.output_notes.write_into(target);
        self.block_commitment.write_into(target);
        self.ref_params.write_into(target);
        self.salt.write_into(target);
    }
}

impl Deserializable for TransactionSummary {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_delta = source.read()?;
        let input_notes = source.read()?;
        let output_notes = source.read()?;
        let block_commitment = source.read()?;
        let ref_params = source.read()?;
        let salt = source.read()?;

        Ok(Self::new(
            account_delta,
            input_notes,
            output_notes,
            block_commitment,
            ref_params,
            salt,
        ))
    }
}
