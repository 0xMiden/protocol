use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::TransactionInputError;
use crate::note::{Note, NoteId, NoteInclusionProof, NoteLocation, Nullifier};
use crate::transaction::InputNoteCommitment;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, MAX_INPUT_NOTES_PER_TX, Word};

// TO INPUT NOTE COMMITMENT
// ================================================================================================

/// Specifies the data used by the transaction kernel to commit to a note.
///
/// The commitment is composed of:
///
/// - nullifier, which prevents double spend and provides unlinkability.
/// - an optional note commitment, which allows for delayed note authentication.
pub trait ToInputNoteCommitments {
    fn nullifier(&self) -> Nullifier;
    fn note_commitment(&self) -> Option<Word>;
}

// INPUT NOTES
// ================================================================================================

/// Input notes for a transaction, empty if the transaction does not consume notes.
///
/// This structure is generic over `T`, so it can be used to create the input notes for transaction
/// execution, which require the note's details to run the transaction kernel, and the input notes
/// for proof verification, which require only the commitment data.
#[derive(Debug, Clone)]
pub struct InputNotes<T> {
    notes: Vec<T>,
    commitment: Word,
}

impl<T: ToInputNoteCommitments> InputNotes<T> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns new [InputNotes] instantiated from the provided vector of notes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The total number of notes is greater than [`MAX_INPUT_NOTES_PER_TX`].
    /// - The vector of notes contains duplicates.
    pub fn new(notes: Vec<T>) -> Result<Self, TransactionInputError> {
        if notes.len() > MAX_INPUT_NOTES_PER_TX {
            return Err(TransactionInputError::TooManyInputNotes(notes.len()));
        }

        let mut seen_notes = BTreeSet::new();
        for note in notes.iter() {
            if !seen_notes.insert(note.nullifier().as_word()) {
                return Err(TransactionInputError::DuplicateInputNote(note.nullifier()));
            }
        }

        let commitment = build_input_note_commitment(&notes);

        Ok(Self { notes, commitment })
    }

    /// Returns new [`InputNotes`] instantiated from the provided vector of notes without checking
    /// their validity.
    ///
    /// This is exposed for use in transaction batches, but should generally not be used.
    ///
    /// # Warning
    ///
    /// This does not run the checks from [`InputNotes::new`], so the latter should be preferred.
    pub fn new_unchecked(notes: Vec<T>) -> Self {
        let commitment = build_input_note_commitment(&notes);
        Self { notes, commitment }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a sequential hash of nullifiers for all notes.
    ///
    /// For non empty lists the commitment is defined as:
    ///
    /// > hash(nullifier_0 || noteid0_or_zero || nullifier_1 || noteid1_or_zero || .. || nullifier_n
    /// > || noteidn_or_zero)
    ///
    /// Otherwise defined as ZERO for empty lists.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns total number of input notes.
    pub fn num_notes(&self) -> u16 {
        self.notes
            .len()
            .try_into()
            .expect("by construction, number of notes fits into u16")
    }

    /// Returns true if this [InputNotes] does not contain any notes.
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Returns a reference to the note located at the specified index.
    pub fn get_note(&self, idx: usize) -> &T {
        &self.notes[idx]
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over notes in this [InputNotes].
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.notes.iter()
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Converts self into a vector of input notes.
    pub fn into_vec(self) -> Vec<T> {
        self.notes
    }
}

impl InputNotes<InputNote> {
    /// Returns new [`InputNotes`] instantiated from the provided vector of [notes](Note).
    ///
    /// This constructor internally converts the provided notes into the
    /// [`InputNote::Unauthenticated`], which are then used in the [`Self::new`] constructor.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The total number of notes is greater than [`MAX_INPUT_NOTES_PER_TX`].
    /// - The vector of notes contains duplicates.
    pub fn from_unauthenticated_notes(notes: Vec<Note>) -> Result<Self, TransactionInputError> {
        let input_note_vec =
            notes.into_iter().map(|note| InputNote::Unauthenticated { note }).collect();

        Self::new(input_note_vec)
    }

    /// Returns a vector of input note commitments based on the input notes.
    pub fn to_commitments(&self) -> InputNotes<InputNoteCommitment> {
        let notes = self.notes.iter().map(InputNoteCommitment::from).collect();
        InputNotes::<InputNoteCommitment>::new_unchecked(notes)
    }
}

impl<T> IntoIterator for InputNotes<T> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.notes.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a InputNotes<T> {
    type Item = &'a T;
    type IntoIter = alloc::slice::Iter<'a, T>;

    fn into_iter(self) -> alloc::slice::Iter<'a, T> {
        self.notes.iter()
    }
}

impl<T: PartialEq> PartialEq for InputNotes<T> {
    fn eq(&self, other: &Self) -> bool {
        self.notes == other.notes
    }
}

impl<T: Eq> Eq for InputNotes<T> {}

impl<T: ToInputNoteCommitments> Default for InputNotes<T> {
    fn default() -> Self {
        Self {
            notes: Vec::new(),
            commitment: build_input_note_commitment::<T>(&[]),
        }
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl<T: Serializable> Serializable for InputNotes<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // assert is OK here because we enforce max number of notes in the constructor
        assert!(self.notes.len() <= u16::MAX.into());
        target.write_u16(self.notes.len() as u16);
        target.write_many(&self.notes);
    }
}

impl<T: Deserializable + ToInputNoteCommitments> Deserializable for InputNotes<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_notes = source.read_u16()?;
        let notes = source.read_many::<T>(num_notes.into())?;
        Self::new(notes).map_err(|err| DeserializationError::InvalidValue(format!("{err}")))
    }
}

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

fn build_input_note_commitment<T: ToInputNoteCommitments>(notes: &[T]) -> Word {
    // Note: This implementation must be kept in sync with the kernel's `process_input_notes_data`
    if notes.is_empty() {
        return Word::empty();
    }

    let mut elements: Vec<Felt> = Vec::with_capacity(notes.len() * 2);
    for commitment_data in notes {
        let nullifier = commitment_data.nullifier();
        let empty_word_or_note_commitment =
            &commitment_data.note_commitment().map_or(Word::empty(), |note_id| note_id);

        elements.extend_from_slice(nullifier.as_elements());
        elements.extend_from_slice(empty_word_or_note_commitment.as_elements());
    }
    Hasher::hash_elements(&elements)
}

// INPUT NOTE
// ================================================================================================

const AUTHENTICATED: u8 = 0;
const UNAUTHENTICATED: u8 = 1;

/// An input note for a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputNote {
    /// Input notes whose existences in the chain is verified by the transaction kernel.
    Authenticated { note: Note, proof: NoteInclusionProof },

    /// Input notes whose existence in the chain is not verified by the transaction kernel, but
    /// instead is delegated to the protocol kernels.
    Unauthenticated { note: Note },
}

impl InputNote {
    // CONSTRUCTORS
    // -------------------------------------------------------------------------------------------

    /// Returns an authenticated [InputNote].
    pub fn authenticated(note: Note, proof: NoteInclusionProof) -> Self {
        Self::Authenticated { note, proof }
    }

    /// Returns an unauthenticated [InputNote].
    pub fn unauthenticated(note: Note) -> Self {
        Self::Unauthenticated { note }
    }

    // ACCESSORS
    // -------------------------------------------------------------------------------------------

    /// Returns the ID of the note.
    pub fn id(&self) -> NoteId {
        self.note().id()
    }

    /// Returns a reference to the underlying note.
    pub fn note(&self) -> &Note {
        match self {
            Self::Authenticated { note, .. } => note,
            Self::Unauthenticated { note } => note,
        }
    }

    /// Consumes the [`InputNote`] an converts it to a [`Note`].
    pub fn into_note(self) -> Note {
        match self {
            Self::Authenticated { note, .. } => note,
            Self::Unauthenticated { note } => note,
        }
    }

    /// Returns a reference to the inclusion proof of the note.
    pub fn proof(&self) -> Option<&NoteInclusionProof> {
        match self {
            Self::Authenticated { proof, .. } => Some(proof),
            Self::Unauthenticated { .. } => None,
        }
    }

    /// Returns a reference to the location of the note.
    pub fn location(&self) -> Option<&NoteLocation> {
        self.proof().map(|proof| proof.location())
    }
}

impl From<Vec<Note>> for InputNotes<InputNote> {
    fn from(notes: Vec<Note>) -> Self {
        Self::new_unchecked(notes.into_iter().map(InputNote::unauthenticated).collect::<Vec<_>>())
    }
}

impl ToInputNoteCommitments for InputNote {
    fn nullifier(&self) -> Nullifier {
        self.note().nullifier()
    }

    fn note_commitment(&self) -> Option<Word> {
        match self {
            InputNote::Authenticated { .. } => None,
            InputNote::Unauthenticated { note } => Some(note.commitment()),
        }
    }
}

impl ToInputNoteCommitments for &InputNote {
    fn nullifier(&self) -> Nullifier {
        (*self).nullifier()
    }

    fn note_commitment(&self) -> Option<Word> {
        (*self).note_commitment()
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for InputNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Authenticated { note, proof } => {
                target.write(AUTHENTICATED);
                target.write(note);
                target.write(proof);
            },
            Self::Unauthenticated { note } => {
                target.write(UNAUTHENTICATED);
                target.write(note);
            },
        }
    }
}

impl Deserializable for InputNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            AUTHENTICATED => {
                let note = Note::read_from(source)?;
                let proof = NoteInclusionProof::read_from(source)?;
                Ok(Self::Authenticated { note, proof })
            },
            UNAUTHENTICATED => {
                let note = Note::read_from(source)?;
                Ok(Self::Unauthenticated { note })
            },
            v => Err(DeserializationError::InvalidValue(format!("invalid input note type: {v}"))),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod input_notes_tests {
    use assert_matches::assert_matches;
    use miden_core::Word;

    use super::InputNotes;
    use crate::errors::TransactionInputError;
    use crate::note::Note;
    use crate::transaction::InputNote;

    #[test]
    fn test_duplicate_input_notes() -> anyhow::Result<()> {
        let mock_note = Note::mock_noop(Word::empty());
        let mock_note_nullifier = mock_note.nullifier();
        let mock_note_clone = mock_note.clone();

        let error = InputNotes::new(vec![
            InputNote::Unauthenticated { note: mock_note },
            InputNote::Unauthenticated { note: mock_note_clone },
        ])
        .expect_err("input notes creation should fail");

        assert_matches!(error, TransactionInputError::DuplicateInputNote(nullifier) if nullifier == mock_note_nullifier);

        Ok(())
    }
}
