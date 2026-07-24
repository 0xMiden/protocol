use alloc::vec::Vec;

use crate::account::AccountDelta;
use crate::crypto::SequentialCommit;
use crate::errors::TransactionSummaryError;
use crate::transaction::{InputNote, InputNotes, RawOutputNotes};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

// TRANSACTION SUMMARY
// ================================================================================================

/// The summary of the changes that result from executing a transaction.
///
/// These are the account delta, the consumed and created notes, the commitment to the reference
/// block and the transaction summary parameters (see [`TransactionSummaryParams`]). Because this
/// data is intended to be used for signing a transaction a user-defined salt is included as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSummary {
    account_delta: AccountDelta,
    input_notes: InputNotes<InputNote>,
    output_notes: RawOutputNotes,
    block_commitment: Word,
    params: TransactionSummaryParams,
    salt: Word,
}

impl TransactionSummary {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionSummary`] from the provided parts.
    pub fn new(
        account_delta: AccountDelta,
        input_notes: InputNotes<InputNote>,
        output_notes: RawOutputNotes,
        block_commitment: Word,
        params: TransactionSummaryParams,
        salt: Word,
    ) -> Self {
        Self {
            account_delta,
            input_notes,
            output_notes,
            block_commitment,
            params,
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

    /// Returns the commitment to the reference block of this transaction summary.
    pub fn block_commitment(&self) -> Word {
        self.block_commitment
    }

    /// Returns the [`TransactionSummaryParams`] of this transaction summary.
    pub fn params(&self) -> TransactionSummaryParams {
        self.params
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
        elements.extend_from_slice(self.params.to_word().as_elements());
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
        self.params.write_into(target);
        self.salt.write_into(target);
    }
}

impl Deserializable for TransactionSummary {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_delta = source.read()?;
        let input_notes = source.read()?;
        let output_notes = source.read()?;
        let block_commitment = source.read()?;
        let params = source.read()?;
        let salt = source.read()?;

        Ok(Self::new(
            account_delta,
            input_notes,
            output_notes,
            block_commitment,
            params,
            salt,
        ))
    }
}

// TRANSACTION SUMMARY PARAMS
// ================================================================================================

/// The parameters bound by a [`TransactionSummary`].
///
/// These consist of the transaction's expiration block delta, which is read from the transaction
/// kernel when the summary is created, and three user-defined parameters which can be used to bind
/// custom data to the summary (e.g. a maximum fee).
///
/// The user-defined parameters are opaque: they are bound by the signature over the summary, but
/// no meaning is enforced for them at the protocol level. Any semantics (such as enforcing a
/// maximum fee) must be implemented by the account component that binds them.
///
/// The [`Word`] representation of these parameters is `[expiration_delta, param0, param1,
/// param2]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionSummaryParams {
    expiration_delta: u16,
    user_params: [Felt; 3],
}

impl TransactionSummaryParams {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionSummaryParams`] from the provided parts.
    pub fn new(expiration_delta: u16, user_params: [Felt; 3]) -> Self {
        Self { expiration_delta, user_params }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the expiration block delta of the transaction, or 0 if it has not been set.
    pub fn expiration_delta(&self) -> u16 {
        self.expiration_delta
    }

    /// Returns the user-defined parameters.
    pub fn user_params(&self) -> [Felt; 3] {
        self.user_params
    }

    /// Returns the [`Word`] representation of these parameters.
    pub fn to_word(&self) -> Word {
        Word::from([
            Felt::from(self.expiration_delta),
            self.user_params[0],
            self.user_params[1],
            self.user_params[2],
        ])
    }
}

impl TryFrom<Word> for TransactionSummaryParams {
    type Error = TransactionSummaryError;

    /// Attempts to convert the provided [`Word`] into [`TransactionSummaryParams`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the expiration delta element does not fit into a `u16`.
    fn try_from(word: Word) -> Result<Self, Self::Error> {
        let expiration_delta = u16::try_from(word[0].as_canonical_u64())
            .map_err(|_| TransactionSummaryError::ExpirationDeltaTooLarge(word[0]))?;

        Ok(Self::new(expiration_delta, [word[1], word[2], word[3]]))
    }
}

impl Serializable for TransactionSummaryParams {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.expiration_delta.write_into(target);
        self.user_params.write_into(target);
    }
}

impl Deserializable for TransactionSummaryParams {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let expiration_delta = source.read()?;
        let user_params = source.read()?;

        Ok(Self::new(expiration_delta, user_params))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_summary_params_word_roundtrip() {
        let params = TransactionSummaryParams::new(42, [7u32, 8, 9].map(Felt::from));
        let word = params.to_word();

        assert_eq!(word, Word::from([42u32, 7, 8, 9].map(Felt::from)));
        assert_eq!(TransactionSummaryParams::try_from(word).unwrap(), params);
    }

    #[test]
    fn tx_summary_params_serde_roundtrip() {
        let params = TransactionSummaryParams::new(42, [7u32, 8, 9].map(Felt::from));

        let deserialized = TransactionSummaryParams::read_from_bytes(&params.to_bytes()).unwrap();
        assert_eq!(deserialized, params);
    }

    #[test]
    fn tx_summary_params_reject_out_of_range_expiration_delta() {
        let word = Word::from([u16::MAX as u32 + 1, 0, 0, 0].map(Felt::from));

        assert!(matches!(
            TransactionSummaryParams::try_from(word),
            Err(TransactionSummaryError::ExpirationDeltaTooLarge(_))
        ));
    }
}
