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
use crate::{Felt, WORD_SIZE, Word};

// TRANSACTION SUMMARY
// ================================================================================================

/// The summary of the changes that result from executing a transaction.
///
/// These are the account delta, the consumed and created notes, the commitment to the reference
/// block, the transaction's expiration block delta and the user-defined parameters (see
/// [`TransactionSummaryUserParams`]).
///
/// Because this data is intended to be signed, the user-defined parameters give an account's
/// authentication procedure a way to bind arbitrary additional data to that signature, for example
/// a salt providing replay protection or a maximum fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSummary {
    account_delta: AccountDelta,
    input_notes: InputNotes<InputNote>,
    output_notes: RawOutputNotes,
    block_commitment: Word,
    expiration_delta: u16,
    user_params: TransactionSummaryUserParams,
}

impl TransactionSummary {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The index of the expiration block delta in the commitment preimage, i.e. the number of
    /// elements occupied by the four leading commitments.
    const EXPIRATION_DELTA_IDX: usize = 4 * WORD_SIZE;

    /// The number of elements in the preimage of a [`TransactionSummary`] commitment, i.e. the
    /// length of the vector returned by [`TransactionSummary::to_elements`] (6 words).
    ///
    /// Must match `TX_SUMMARY_NUM_ELEMENTS` in the standard auth library
    /// (crates/miden-standards/asm/standards/auth/mod.masm).
    pub const NUM_ELEMENTS: usize =
        Self::EXPIRATION_DELTA_IDX + 1 + TransactionSummaryUserParams::NUM_ELEMENTS;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionSummary`] from the provided parts.
    pub fn new(
        account_delta: AccountDelta,
        input_notes: InputNotes<InputNote>,
        output_notes: RawOutputNotes,
        block_commitment: Word,
        expiration_delta: u16,
        user_params: TransactionSummaryUserParams,
    ) -> Self {
        Self {
            account_delta,
            input_notes,
            output_notes,
            block_commitment,
            expiration_delta,
            user_params,
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

    /// Returns the expiration block delta of the transaction, or 0 if it has not been set.
    pub fn expiration_delta(&self) -> u16 {
        self.expiration_delta
    }

    /// Returns the user-defined parameters bound by this transaction summary.
    pub fn user_params(&self) -> TransactionSummaryUserParams {
        self.user_params
    }

    /// Returns the elements this transaction summary commits to, i.e. the preimage of
    /// [`TransactionSummary::to_commitment`].
    ///
    /// The returned vector contains [`TransactionSummary::NUM_ELEMENTS`] elements laid out as:
    ///
    /// ```text
    /// [
    ///     ACCOUNT_DELTA_COMMITMENT, INPUT_NOTES_COMMITMENT, OUTPUT_NOTES_COMMITMENT,
    ///     BLOCK_COMMITMENT, [expiration_delta, user_param0, user_param1, user_param2],
    ///     [user_param3, user_param4, user_param5, user_param6],
    /// ]
    /// ```
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Computes the commitment to the [`TransactionSummary`].
    ///
    /// This can be used to sign the transaction.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    // PARAMETER DECODING
    // --------------------------------------------------------------------------------------------

    /// Decodes the transaction's expiration block delta and its [`TransactionSummaryUserParams`]
    /// from the preimage of a transaction summary commitment.
    ///
    /// `elements` must be a full preimage as returned by [`TransactionSummary::to_elements`]. The
    /// four leading commitments are not decoded because they cannot be inverted: a caller
    /// reconstructing a summary from a preimage must rebuild the committed data from its own state,
    /// pass it to [`TransactionSummary::new`] alongside the decoded values and check the result
    /// against [`TransactionSummary::to_commitment`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `elements` does not contain exactly [`TransactionSummary::NUM_ELEMENTS`] elements.
    /// - the expiration block delta element does not fit into a `u16`.
    pub fn try_params_from_elements(
        elements: &[Felt],
    ) -> Result<(u16, TransactionSummaryUserParams), TransactionSummaryError> {
        if elements.len() != Self::NUM_ELEMENTS {
            return Err(TransactionSummaryError::InvalidPreimageLength {
                actual: elements.len(),
                expected: Self::NUM_ELEMENTS,
            });
        }

        let expiration_delta_element = elements[Self::EXPIRATION_DELTA_IDX];
        let expiration_delta =
            u16::try_from(expiration_delta_element.as_canonical_u64()).map_err(|_| {
                TransactionSummaryError::ExpirationDeltaTooLarge(expiration_delta_element)
            })?;

        let user_params = elements[Self::EXPIRATION_DELTA_IDX + 1..]
            .try_into()
            .expect("preimage length was validated above");

        Ok((expiration_delta, TransactionSummaryUserParams::new(user_params)))
    }
}

/// The auth library absorbs the preimage word by word, so its length must stay word-aligned.
const _: () = assert!(TransactionSummary::NUM_ELEMENTS.is_multiple_of(WORD_SIZE));

impl SequentialCommit for TransactionSummary {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(Self::NUM_ELEMENTS);
        elements.extend_from_slice(self.account_delta.to_commitment().as_elements());
        elements.extend_from_slice(self.input_notes.commitment().as_elements());
        elements.extend_from_slice(self.output_notes.commitment().as_elements());
        elements.extend_from_slice(self.block_commitment.as_elements());
        elements.push(Felt::from(self.expiration_delta));
        elements.extend_from_slice(self.user_params.as_elements());
        elements
    }
}

impl Serializable for TransactionSummary {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.account_delta.write_into(target);
        self.input_notes.write_into(target);
        self.output_notes.write_into(target);
        self.block_commitment.write_into(target);
        self.expiration_delta.write_into(target);
        self.user_params.write_into(target);
    }
}

impl Deserializable for TransactionSummary {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_delta = source.read()?;
        let input_notes = source.read()?;
        let output_notes = source.read()?;
        let block_commitment = source.read()?;
        let expiration_delta = source.read()?;
        let user_params = source.read()?;

        Ok(Self::new(
            account_delta,
            input_notes,
            output_notes,
            block_commitment,
            expiration_delta,
            user_params,
        ))
    }
}

// TRANSACTION SUMMARY USER PARAMS
// ================================================================================================

/// The user-defined parameters bound by a [`TransactionSummary`].
///
/// These are [`TransactionSummaryUserParams::NUM_ELEMENTS`] elements supplied by the account's
/// authentication procedure when the summary is created.
///
/// The parameters are opaque: they are bound by the signature over the summary, but no meaning is
/// enforced for any of them at the protocol level. Any semantics - using some of them as a salt for
/// replay protection or binding a maximum fee, for example - must be implemented by the account
/// component that supplies them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionSummaryUserParams {
    elements: [Felt; Self::NUM_ELEMENTS],
}

impl TransactionSummaryUserParams {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of user-defined elements bound by a [`TransactionSummary`].
    pub const NUM_ELEMENTS: usize = 7;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates new [`TransactionSummaryUserParams`] from the provided elements.
    pub fn new(elements: [Felt; Self::NUM_ELEMENTS]) -> Self {
        Self { elements }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the user-defined elements in the order in which they are hashed into the
    /// [`TransactionSummary`] commitment.
    pub fn as_elements(&self) -> &[Felt; Self::NUM_ELEMENTS] {
        &self.elements
    }
}

impl Serializable for TransactionSummaryUserParams {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.elements.write_into(target);
    }
}

impl Deserializable for TransactionSummaryUserParams {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(source.read()?))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::ONE;
    use crate::account::{AccountId, AccountStoragePatch, AccountVaultDelta};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;

    /// The expiration delta and user parameters used by the tests below.
    const EXPIRATION_DELTA: u16 = 42;
    const USER_PARAMS: [u32; TransactionSummaryUserParams::NUM_ELEMENTS] = [1, 2, 3, 4, 5, 6, 7];

    /// Builds a transaction summary over an empty delta and no notes, binding the parameters above.
    fn mock_summary() -> TransactionSummary {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let account_delta = AccountDelta::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultDelta::default(),
            None,
            ONE,
        )
        .unwrap();

        TransactionSummary::new(
            account_delta,
            InputNotes::new(Vec::new()).unwrap(),
            RawOutputNotes::new(Vec::new()).unwrap(),
            Word::from([9u32, 10, 11, 12].map(Felt::from)),
            EXPIRATION_DELTA,
            TransactionSummaryUserParams::new(USER_PARAMS.map(Felt::from)),
        )
    }

    #[test]
    fn tx_summary_params_element_roundtrip() {
        let summary = mock_summary();
        let elements = summary.to_elements();

        assert_eq!(elements.len(), TransactionSummary::NUM_ELEMENTS);
        assert_eq!(
            &elements[TransactionSummary::EXPIRATION_DELTA_IDX..],
            [
                Felt::from(EXPIRATION_DELTA),
                Felt::from(USER_PARAMS[0]),
                Felt::from(USER_PARAMS[1]),
                Felt::from(USER_PARAMS[2]),
                Felt::from(USER_PARAMS[3]),
                Felt::from(USER_PARAMS[4]),
                Felt::from(USER_PARAMS[5]),
                Felt::from(USER_PARAMS[6]),
            ]
        );

        let (expiration_delta, user_params) =
            TransactionSummary::try_params_from_elements(&elements).unwrap();
        assert_eq!(expiration_delta, EXPIRATION_DELTA);
        assert_eq!(user_params, summary.user_params());
    }

    #[test]
    fn tx_summary_serde_roundtrip() {
        let summary = mock_summary();

        let deserialized = TransactionSummary::read_from_bytes(&summary.to_bytes()).unwrap();
        assert_eq!(deserialized, summary);
    }

    #[test]
    fn tx_summary_params_reject_out_of_range_expiration_delta() {
        let mut elements = mock_summary().to_elements();
        elements[TransactionSummary::EXPIRATION_DELTA_IDX] = Felt::from(u16::MAX as u32 + 1);

        assert_matches!(
            TransactionSummary::try_params_from_elements(&elements),
            Err(TransactionSummaryError::ExpirationDeltaTooLarge(_))
        );
    }

    #[test]
    fn tx_summary_params_reject_preimage_of_wrong_length() {
        let mut elements = mock_summary().to_elements();
        elements.pop();

        assert_matches!(
            TransactionSummary::try_params_from_elements(&elements),
            Err(TransactionSummaryError::InvalidPreimageLength { actual, expected })
                if actual == TransactionSummary::NUM_ELEMENTS - 1
                    && expected == TransactionSummary::NUM_ELEMENTS
        );
    }
}
