use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::Word;
use crate::errors::TransactionHeaderError;
use crate::note::NoteHeader;
use crate::transaction::{
    AccountId,
    ExecutedTransaction,
    InputNoteCommitment,
    InputNotes,
    ProvenTransaction,
    RawOutputNotes,
    TransactionCommitments,
    TransactionId,
};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// A transaction header derived from a
/// [`ProvenTransaction`](crate::transaction::ProvenTransaction).
///
/// The header is essentially a direct copy of the transaction's public commitments, in particular
/// the initial and final account state commitment as well as all nullifiers of consumed notes and
/// all note IDs of created notes. While account updates may be aggregated and notes may be erased
/// as part of batch and block building, the header retains the original transaction's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionHeader {
    id: TransactionId,
    account_id: AccountId,
    initial_state_commitment: Word,
    final_state_commitment: Word,
    input_notes: InputNotes<InputNoteCommitment>,
    output_notes: Vec<NoteHeader>,
}

impl TransactionHeader {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new [`TransactionHeader`] from the provided parameters.
    ///
    /// The [`TransactionId`] is computed from the provided parameters, committing to the initial
    /// and final account commitments and the input and output note commitments.
    ///
    /// The input notes and output notes must be in the same order as they appeared in the
    /// transaction that this header represents, otherwise an incorrect ID will be computed.
    ///
    /// Note that this cannot validate that the [`AccountId`] is valid with respect to the other
    /// data. This must be validated outside of this type.
    ///
    /// # Errors
    ///
    /// Returns an error if the input notes contain duplicate nullifiers, the output notes contain
    /// duplicate note IDs, or an unauthenticated input note is also created by the transaction.
    /// Authenticated input note commitments do not carry note IDs, so overlap involving those notes
    /// cannot be detected from a transaction header.
    pub fn new(
        account_id: AccountId,
        initial_state_commitment: Word,
        final_state_commitment: Word,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<NoteHeader>,
    ) -> Result<Self, TransactionHeaderError> {
        let mut input_nullifiers = BTreeSet::new();
        for input_note in &input_notes {
            if !input_nullifiers.insert(input_note.nullifier()) {
                return Err(TransactionHeaderError::DuplicateInputNote(input_note.nullifier()));
            }
        }

        let mut output_note_ids = BTreeSet::new();
        for output_note in &output_notes {
            if !output_note_ids.insert(output_note.id()) {
                return Err(TransactionHeaderError::DuplicateOutputNote(output_note.id()));
            }
        }

        for input_note in input_notes.iter().filter_map(InputNoteCommitment::header) {
            if output_note_ids.contains(&input_note.id()) {
                return Err(TransactionHeaderError::NoteCreatedAndConsumed(input_note.id()));
            }
        }

        let input_notes_commitment = input_notes.commitment();
        let output_notes_commitment = RawOutputNotes::compute_commitment(output_notes.iter());

        let id = TransactionId::new(TransactionCommitments::new(
            initial_state_commitment,
            final_state_commitment,
            input_notes_commitment,
            output_notes_commitment,
        ));

        Ok(Self {
            id,
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
        })
    }

    /// Constructs a new [`TransactionHeader`] from the provided parameters.
    ///
    /// # Warning
    ///
    /// This does not validate the internal consistency of the data. Prefer [`Self::new`] whenever
    /// possible.
    pub(crate) fn new_unchecked(
        id: TransactionId,
        account_id: AccountId,
        initial_state_commitment: Word,
        final_state_commitment: Word,
        input_notes: InputNotes<InputNoteCommitment>,
        output_notes: Vec<NoteHeader>,
    ) -> Self {
        Self {
            id,
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the unique identifier of this transaction.
    pub fn id(&self) -> TransactionId {
        self.id
    }

    /// Returns the ID of the account against which this transaction was executed.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Returns a commitment to the state of the account before this update is applied.
    ///
    /// This is equal to [`Word::empty()`] for new accounts.
    pub fn initial_state_commitment(&self) -> Word {
        self.initial_state_commitment
    }

    /// Returns a commitment to the state of the account after this update is applied.
    pub fn final_state_commitment(&self) -> Word {
        self.final_state_commitment
    }

    /// Returns a reference to the consumed notes of the transaction.
    ///
    /// The returned input note commitments have the same order as the transaction to which the
    /// header belongs.
    ///
    /// Note that the note may have been erased at the batch or block level, so it may not be
    /// present there.
    pub fn input_notes(&self) -> &InputNotes<InputNoteCommitment> {
        &self.input_notes
    }

    /// Returns a reference to the ID and metadata of the output notes created by the transaction.
    ///
    /// The returned output note data has the same order as the transaction to which the header
    /// belongs.
    ///
    /// Note that the note may have been erased at the batch or block level, so it may not be
    /// present there.
    pub fn output_notes(&self) -> &[NoteHeader] {
        &self.output_notes
    }
}

impl From<&ProvenTransaction> for TransactionHeader {
    /// Constructs a [`TransactionHeader`] from a [`ProvenTransaction`].
    fn from(tx: &ProvenTransaction) -> Self {
        // SAFETY: The data in a proven transaction is guaranteed to be internally consistent and so
        // we can skip the consistency checks by the `new` constructor.
        TransactionHeader::new_unchecked(
            tx.id(),
            tx.account_id(),
            tx.account_update().initial_state_commitment(),
            tx.account_update().final_state_commitment(),
            tx.input_notes().clone(),
            tx.output_notes().iter().map(|note| *note.header()).collect(),
        )
    }
}

impl From<&ExecutedTransaction> for TransactionHeader {
    /// Constructs a [`TransactionHeader`] from a [`ExecutedTransaction`].
    fn from(tx: &ExecutedTransaction) -> Self {
        TransactionHeader::new_unchecked(
            tx.id(),
            tx.account_id(),
            tx.initial_account().initial_commitment(),
            tx.final_account().to_commitment(),
            tx.input_notes().to_commitments(),
            tx.output_notes().iter().map(|n| *n.header()).collect(),
        )
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for TransactionHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self {
            id: _,
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
        } = self;

        account_id.write_into(target);
        initial_state_commitment.write_into(target);
        final_state_commitment.write_into(target);
        input_notes.write_into(target);
        output_notes.write_into(target);
    }
}

impl Deserializable for TransactionHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let account_id = <AccountId>::read_from(source)?;
        let initial_state_commitment = <Word>::read_from(source)?;
        let final_state_commitment = <Word>::read_from(source)?;
        let input_notes = <InputNotes<InputNoteCommitment>>::read_from(source)?;
        let output_notes = <Vec<NoteHeader>>::read_from(source)?;

        Self::new(
            account_id,
            initial_state_commitment,
            final_state_commitment,
            input_notes,
            output_notes,
        )
        .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::TransactionHeader;
    use crate::Word;
    use crate::account::AccountId;
    use crate::errors::TransactionHeaderError;
    use crate::note::Note;
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
    use crate::transaction::{
        InputNoteCommitment,
        InputNotes,
        TransactionCommitments,
        TransactionId,
    };
    use crate::utils::serde::{Deserializable, DeserializationError, Serializable};

    fn account_id() -> AccountId {
        AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap()
    }

    #[test]
    fn rejects_duplicate_input_notes() {
        let note = Note::mock_noop(Word::empty());
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));
        let inputs = InputNotes::new_unchecked(vec![input.clone(), input]);

        let error = TransactionHeader::new(
            account_id(),
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            inputs,
            vec![],
        )
        .unwrap_err();

        assert_matches!(
            error,
            TransactionHeaderError::DuplicateInputNote(nullifier)
                if nullifier == note.nullifier()
        );
    }

    #[test]
    fn rejects_duplicate_output_notes() {
        let note = Note::mock_noop(Word::empty());

        let error = TransactionHeader::new(
            account_id(),
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            InputNotes::default(),
            vec![*note.header(), *note.header()],
        )
        .unwrap_err();

        assert_matches!(
            error,
            TransactionHeaderError::DuplicateOutputNote(note_id) if note_id == note.id()
        );
    }

    #[test]
    fn rejects_note_created_and_consumed() {
        let note = Note::mock_noop(Word::empty());
        let input =
            InputNoteCommitment::from_parts_unchecked(note.nullifier(), Some(*note.header()));

        let error = TransactionHeader::new(
            account_id(),
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            InputNotes::new(vec![input]).unwrap(),
            vec![*note.header()],
        )
        .unwrap_err();

        assert_matches!(
            error,
            TransactionHeaderError::NoteCreatedAndConsumed(note_id) if note_id == note.id()
        );
    }

    #[test]
    fn deserialization_rejects_duplicate_output_notes() {
        let note = Note::mock_noop(Word::empty());
        let invalid_header = TransactionHeader::new_unchecked(
            TransactionId::new(TransactionCommitments::new(
                Word::empty(),
                Word::empty(),
                Word::empty(),
                Word::empty(),
            )),
            account_id(),
            Word::from([1_u32, 2, 3, 4]),
            Word::from([5_u32, 6, 7, 8]),
            InputNotes::default(),
            vec![*note.header(), *note.header()],
        );

        let error = TransactionHeader::read_from_bytes(&invalid_header.to_bytes()).unwrap_err();

        assert_matches!(
            error,
            DeserializationError::InvalidValue(message)
                if message
                    == format!(
                        "output note {} appears twice in the transaction header",
                        note.id()
                    )
        );
    }
}
