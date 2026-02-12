use alloc::vec::Vec;

use crate::account::AccountDelta;
use crate::crypto::SequentialCommit;
use crate::transaction::{InputNote, InputNotes, OutputNotes};
use crate::utils::{Deserializable, Serializable};
use crate::{Felt, Word};

/// The summary of the changes that result from executing a transaction.
///
/// These are the account delta and the consumed and created notes. Because this data is intended to
/// be used for signing a transaction a user-defined salt is included as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSummary {
    account_delta: AccountDelta,
    input_notes: InputNotes<InputNote>,
    output_notes: OutputNotes,
    salt: Word,
}

impl TransactionSummary {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionSummary`] from the provided parts.
    pub fn new(
        account_delta: AccountDelta,
        input_notes: InputNotes<InputNote>,
        output_notes: OutputNotes,
        salt: Word,
    ) -> Self {
        Self {
            account_delta,
            input_notes,
            output_notes,
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
    pub fn output_notes(&self) -> &OutputNotes {
        &self.output_notes
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
        let mut elements = Vec::with_capacity(16);
        elements.extend_from_slice(self.account_delta.to_commitment().as_elements());
        elements.extend_from_slice(self.input_notes.commitment().as_elements());
        elements.extend_from_slice(self.output_notes.commitment().as_elements());
        elements.extend_from_slice(self.salt.as_elements());
        elements
    }
}

impl Serializable for TransactionSummary {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        self.account_delta.write_into(target);
        self.input_notes.write_into(target);
        self.output_notes.write_into(target);
        self.salt.write_into(target);
    }
}

impl Deserializable for TransactionSummary {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_processor::DeserializationError> {
        let account_delta = source.read()?;
        let input_notes = source.read()?;
        let output_notes = source.read()?;
        let salt = source.read()?;

        Ok(Self::new(account_delta, input_notes, output_notes, salt))
    }
}
