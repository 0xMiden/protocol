use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::account::AccountHeader;
use crate::asset::FungibleAsset;
use crate::block::BlockNumber;
use crate::errors::TransactionOutputError;
use crate::note::{
    Note,
    NoteAssets,
    NoteHeader,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    PartialNote,
    compute_note_commitment,
};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, MAX_OUTPUT_NOTES_PER_TX, Word};

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
    pub output_notes: OutputNotes,
    /// The fee of the transaction.
    pub fee: FungibleAsset,
    /// Defines up to which block the transaction is considered valid.
    pub expiration_block_num: BlockNumber,
}

impl TransactionOutputs {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The index of the word at which the final account nonce is stored on the output stack.
    pub const OUTPUT_NOTES_COMMITMENT_WORD_IDX: usize = 0;

    /// The index of the word at which the account update commitment is stored on the output stack.
    pub const ACCOUNT_UPDATE_COMMITMENT_WORD_IDX: usize = 1;

    /// The index of the word at which the fee asset is stored on the output stack.
    pub const FEE_ASSET_WORD_IDX: usize = 2;

    /// The index of the item at which the expiration block height is stored on the output stack.
    pub const EXPIRATION_BLOCK_ELEMENT_IDX: usize = 12;
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
        let output_notes = OutputNotes::read_from(source)?;
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

// OUTPUT NOTES
// ================================================================================================

/// Contains a list of output notes of a transaction. The list can be empty if the transaction does
/// not produce any notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputNotes {
    notes: Vec<OutputNote>,
    commitment: Word,
}

impl OutputNotes {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns new [OutputNotes] instantiated from the provide vector of notes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The total number of notes is greater than [`MAX_OUTPUT_NOTES_PER_TX`].
    /// - The vector of notes contains duplicates.
    pub fn new(notes: Vec<OutputNote>) -> Result<Self, TransactionOutputError> {
        if notes.len() > MAX_OUTPUT_NOTES_PER_TX {
            return Err(TransactionOutputError::TooManyOutputNotes(notes.len()));
        }

        let mut seen_notes = BTreeSet::new();
        for note in notes.iter() {
            if !seen_notes.insert(note.id()) {
                return Err(TransactionOutputError::DuplicateOutputNote(note.id()));
            }
        }

        let commitment = Self::compute_commitment(notes.iter().map(OutputNote::header));

        Ok(Self { notes, commitment })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment to the output notes.
    ///
    /// The commitment is computed as a sequential hash of (hash, metadata) tuples for the notes
    /// created in a transaction.
    pub fn commitment(&self) -> Word {
        self.commitment
    }
    /// Returns total number of output notes.
    pub fn num_notes(&self) -> usize {
        self.notes.len()
    }

    /// Returns true if this [OutputNotes] does not contain any notes.
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Returns a reference to the note located at the specified index.
    pub fn get_note(&self, idx: usize) -> &OutputNote {
        &self.notes[idx]
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over notes in this [OutputNotes].
    pub fn iter(&self) -> impl Iterator<Item = &OutputNote> {
        self.notes.iter()
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes a commitment to output notes.
    ///
    /// - For an empty list, [`Word::empty`] is returned.
    /// - For a non-empty list of notes, this is a sequential hash of (note_id, metadata_commitment)
    ///   tuples for the notes created in a transaction, where `metadata_commitment` is the return
    ///   value of [`NoteMetadata::to_commitment`].
    pub(crate) fn compute_commitment<'header>(
        notes: impl ExactSizeIterator<Item = &'header NoteHeader>,
    ) -> Word {
        if notes.len() == 0 {
            return Word::empty();
        }

        let mut elements: Vec<Felt> = Vec::with_capacity(notes.len() * 8);
        for note_header in notes {
            elements.extend_from_slice(note_header.id().as_elements());
            elements.extend_from_slice(note_header.metadata().to_commitment().as_elements());
        }

        Hasher::hash_elements(&elements)
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for OutputNotes {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // assert is OK here because we enforce max number of notes in the constructor
        assert!(self.notes.len() <= u16::MAX.into());
        target.write_u16(self.notes.len() as u16);
        target.write_many(&self.notes);
    }
}

impl Deserializable for OutputNotes {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_notes = source.read_u16()?;
        let notes = source.read_many::<OutputNote>(num_notes.into())?;
        Self::new(notes).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// OUTPUT NOTE
// ================================================================================================

const FULL: u8 = 0;
const PARTIAL: u8 = 1;
const HEADER: u8 = 2;

/// The types of note outputs supported by the transaction kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputNote {
    Full(Note),
    Partial(PartialNote),
    Header(NoteHeader),
}

impl OutputNote {
    /// The assets contained in the note.
    pub fn assets(&self) -> Option<&NoteAssets> {
        match self {
            OutputNote::Full(note) => Some(note.assets()),
            OutputNote::Partial(note) => Some(note.assets()),
            OutputNote::Header(_) => None,
        }
    }

    /// Unique note identifier.
    ///
    /// This value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        match self {
            OutputNote::Full(note) => note.id(),
            OutputNote::Partial(note) => note.id(),
            OutputNote::Header(note) => note.id(),
        }
    }

    /// Returns the recipient of the processed [`Full`](OutputNote::Full) output note, [`None`] if
    /// the note type is not [`Full`](OutputNote::Full).
    ///
    /// See [crate::note::NoteRecipient] for more details.
    pub fn recipient(&self) -> Option<&NoteRecipient> {
        match self {
            OutputNote::Full(note) => Some(note.recipient()),
            OutputNote::Partial(_) => None,
            OutputNote::Header(_) => None,
        }
    }

    /// Returns the recipient digest of the processed [`Full`](OutputNote::Full) or
    /// [`Partial`](OutputNote::Partial) output note. Returns [`None`] if the note type is
    /// [`Header`](OutputNote::Header).
    ///
    /// See [crate::note::NoteRecipient] for more details.
    pub fn recipient_digest(&self) -> Option<Word> {
        match self {
            OutputNote::Full(note) => Some(note.recipient().digest()),
            OutputNote::Partial(note) => Some(note.recipient_digest()),
            OutputNote::Header(_) => None,
        }
    }

    /// Note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        match self {
            OutputNote::Full(note) => note.metadata(),
            OutputNote::Partial(note) => note.metadata(),
            OutputNote::Header(note) => note.metadata(),
        }
    }

    /// Erase private note information.
    ///
    /// Specifically:
    /// - Full private notes are converted into note headers.
    /// - All partial notes are converted into note headers.
    pub fn shrink(&self) -> Self {
        match self {
            OutputNote::Full(note) if note.metadata().is_private() => {
                OutputNote::Header(note.header().clone())
            },
            OutputNote::Partial(note) => OutputNote::Header(note.header().clone()),
            _ => self.clone(),
        }
    }

    /// Returns a reference to the [`NoteHeader`] of this note.
    pub fn header(&self) -> &NoteHeader {
        match self {
            OutputNote::Full(note) => note.header(),
            OutputNote::Partial(note) => note.header(),
            OutputNote::Header(header) => header,
        }
    }

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
    pub fn commitment(&self) -> Word {
        compute_note_commitment(self.id(), self.metadata())
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for OutputNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            OutputNote::Full(note) => {
                target.write(FULL);
                target.write(note);
            },
            OutputNote::Partial(note) => {
                target.write(PARTIAL);
                target.write(note);
            },
            OutputNote::Header(note) => {
                target.write(HEADER);
                target.write(note);
            },
        }
    }
}

impl Deserializable for OutputNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            FULL => Ok(OutputNote::Full(Note::read_from(source)?)),
            PARTIAL => Ok(OutputNote::Partial(PartialNote::read_from(source)?)),
            HEADER => Ok(OutputNote::Header(NoteHeader::read_from(source)?)),
            v => Err(DeserializationError::InvalidValue(format!("invalid note type: {v}"))),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod output_notes_tests {
    use assert_matches::assert_matches;

    use super::OutputNotes;
    use crate::Word;
    use crate::errors::TransactionOutputError;
    use crate::note::Note;
    use crate::transaction::OutputNote;

    #[test]
    fn test_duplicate_output_notes() -> anyhow::Result<()> {
        let mock_note = Note::mock_noop(Word::empty());
        let mock_note_id = mock_note.id();
        let mock_note_clone = mock_note.clone();

        let error =
            OutputNotes::new(vec![OutputNote::Full(mock_note), OutputNote::Full(mock_note_clone)])
                .expect_err("input notes creation should fail");

        assert_matches!(error, TransactionOutputError::DuplicateOutputNote(note_id) if note_id == mock_note_id);

        Ok(())
    }
}
