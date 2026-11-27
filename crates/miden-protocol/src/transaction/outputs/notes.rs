use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::constants::NOTE_MAX_SIZE;
use crate::errors::{OutputNoteError, TransactionOutputError};
use crate::note::{
    Note,
    NoteAssets,
    NoteAttachments,
    NoteDetailsCommitment,
    NoteHeader,
    NoteId,
    NoteMetadata,
    NoteRecipient,
    PartialNote,
};
use crate::utils::serde::Serializable;
use crate::{Felt, Hasher, MAX_OUTPUT_NOTES_PER_TX, Word};

// OUTPUT NOTE COLLECTION
// ================================================================================================

/// Contains a list of output notes of a transaction. The list can be empty if the transaction does
/// not produce any notes.
///
/// This struct is generic over the note type `N`, allowing it to be used with both
/// [`RawOutputNote`] (in [`ExecutedTransaction`](crate::transaction::ExecutedTransaction)) and
/// [`OutputNote`] (in [`ProvenTransaction`](crate::transaction::ProvenTransaction)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputNoteCollection<N> {
    notes: Vec<N>,
    commitment: Word,
}

impl<N> OutputNoteCollection<N>
where
    for<'a> &'a NoteHeader: From<&'a N>,
    for<'a> NoteId: From<&'a N>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns new [OutputNoteCollection] instantiated from the provided vector of notes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The total number of notes is greater than [`MAX_OUTPUT_NOTES_PER_TX`].
    /// - The vector of notes contains duplicates.
    pub fn new(notes: Vec<N>) -> Result<Self, TransactionOutputError> {
        if notes.len() > MAX_OUTPUT_NOTES_PER_TX {
            return Err(TransactionOutputError::TooManyOutputNotes(notes.len()));
        }

        let mut seen_notes = BTreeSet::new();
        for note in notes.iter() {
            let note_id = NoteId::from(note);
            if !seen_notes.insert(note_id) {
                return Err(TransactionOutputError::DuplicateOutputNote(note_id));
            }
        }

        let commitment = Self::compute_commitment(notes.iter().map(<&NoteHeader>::from));

        Ok(Self { notes, commitment })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment to the output notes.
    ///
    /// The commitment is computed as a sequential hash of `(note_details_commitment,
    /// metadata_commitment)` tuples for the notes created in a transaction.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns total number of output notes.
    pub fn num_notes(&self) -> usize {
        self.notes.len()
    }

    /// Returns true if this [OutputNoteCollection] does not contain any notes.
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Returns a reference to the note located at the specified index.
    pub fn get_note(&self, idx: usize) -> &N {
        &self.notes[idx]
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over notes in this [OutputNoteCollection].
    pub fn iter(&self) -> impl Iterator<Item = &N> {
        self.notes.iter()
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes a commitment to output notes.
    ///
    /// This is a sequential hash of `(note_details_commitment, metadata_commitment)` tuples for
    /// the notes created in a transaction, where `metadata_commitment` is the return value of
    /// [`NoteMetadata::to_commitment`]. An empty list uses the canonical Eidos empty hash.
    pub(crate) fn compute_commitment<'header>(
        notes: impl ExactSizeIterator<Item = &'header NoteHeader>,
    ) -> Word {
        let mut elements: Vec<Felt> = Vec::with_capacity(notes.len() * 8);
        for note_header in notes {
            elements.extend_from_slice(note_header.details_commitment().as_elements());
            elements.extend_from_slice(note_header.metadata().to_commitment().as_elements());
        }

        Hasher::hash_elements(&elements)
    }
}

impl<N> IntoIterator for OutputNoteCollection<N> {
    type Item = N;

    type IntoIter = alloc::vec::IntoIter<N>;

    fn into_iter(self) -> Self::IntoIter {
        self.notes.into_iter()
    }
}

// RAW OUTPUT NOTES
// ================================================================================================

/// Output notes produced during transaction execution (before proving).
///
/// Contains [`RawOutputNote`] instances which represent notes as they exist immediately after
/// transaction execution.
pub type RawOutputNotes = OutputNoteCollection<RawOutputNote>;

/// The types of note outputs produced during transaction execution (before proving).
///
/// This enum represents notes as they exist immediately after transaction execution,
/// before they are processed for inclusion in a proven transaction. It includes:
/// - Full notes with all details (public or private)
/// - Partial notes (notes created with only recipient digest, not full recipient details)
///
/// During proving, these are converted to [`OutputNote`] via the
/// [`into_output_note`](Self::into_output_note) method, which enforces size limits on public notes
/// and converts private/partial notes to headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawOutputNote {
    Full(Note),
    Partial(PartialNote),
}

impl RawOutputNote {
    /// The assets contained in the note.
    pub fn assets(&self) -> &NoteAssets {
        match self {
            Self::Full(note) => note.assets(),
            Self::Partial(note) => note.assets(),
        }
    }

    /// Unique note identifier.
    ///
    /// This value commits to the note details and metadata.
    pub fn id(&self) -> NoteId {
        match self {
            Self::Full(note) => note.id(),
            Self::Partial(note) => note.id(),
        }
    }

    /// Returns the commitment to the note's details, excluding metadata.
    pub fn details_commitment(&self) -> NoteDetailsCommitment {
        match self {
            Self::Full(note) => note.details_commitment(),
            Self::Partial(note) => note.details_commitment(),
        }
    }

    /// Returns the recipient of the processed [`Full`](RawOutputNote::Full) output note, [`None`]
    /// if the note type is not [`Full`](RawOutputNote::Full).
    ///
    /// See [crate::note::NoteRecipient] for more details.
    pub fn recipient(&self) -> Option<&NoteRecipient> {
        match self {
            Self::Full(note) => Some(note.recipient()),
            Self::Partial(_) => None,
        }
    }

    /// Returns the recipient digest of the output note.
    ///
    /// See [crate::note::NoteRecipient] for more details.
    pub fn recipient_digest(&self) -> Word {
        match self {
            RawOutputNote::Full(note) => note.recipient().digest(),
            RawOutputNote::Partial(note) => note.recipient_digest(),
        }
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        match self {
            Self::Full(note) => note.metadata(),
            Self::Partial(note) => note.metadata(),
        }
    }

    /// Converts this output note to a proven output note.
    ///
    /// This method performs the following transformations:
    /// - Private notes (full or partial) are converted into note headers (only public info
    ///   retained).
    /// - Full public notes are wrapped in [`PublicOutputNote`], which enforces size limits
    ///
    /// # Errors
    /// Returns an error if a public note exceeds the maximum allowed size ([`NOTE_MAX_SIZE`]).
    pub fn into_output_note(self) -> Result<OutputNote, OutputNoteError> {
        match self {
            Self::Full(note) if note.metadata().is_private() => {
                let details_commitment = note.details_commitment();
                let (_, metadata, _, attachments) = note.into_parts();
                let note_header = NoteHeader::new(details_commitment, metadata);
                Ok(OutputNote::Private(PrivateOutputNote::new(note_header, attachments)?))
            },
            Self::Full(note) => Ok(OutputNote::Public(PublicOutputNote::new(note)?)),
            Self::Partial(note) => {
                let (_, header, attachments) = note.into_parts();
                Ok(OutputNote::Private(PrivateOutputNote::new(header, attachments)?))
            },
        }
    }

    /// Returns a reference to the [`NoteHeader`] of this note.
    pub fn header(&self) -> &NoteHeader {
        match self {
            Self::Full(note) => note.header(),
            Self::Partial(note) => note.header(),
        }
    }

    /// Returns a reference to the note's attachments.
    pub fn attachments(&self) -> &NoteAttachments {
        match self {
            Self::Full(note) => note.attachments(),
            Self::Partial(note) => note.attachments(),
        }
    }
}

impl From<&RawOutputNote> for NoteId {
    fn from(note: &RawOutputNote) -> Self {
        note.id()
    }
}

impl<'note> From<&'note RawOutputNote> for &'note NoteHeader {
    fn from(note: &'note RawOutputNote) -> Self {
        note.header()
    }
}

// OUTPUT NOTES
// ================================================================================================

/// Output notes in a proven transaction.
///
/// Contains [`OutputNote`] instances which have been processed for inclusion in proven
/// transactions, with size limits enforced on public notes.
pub type OutputNotes = OutputNoteCollection<OutputNote>;

/// Output note types that can appear in a proven transaction.
///
/// This enum represents the final form of output notes after proving. Unlike [`RawOutputNote`],
/// this enum:
/// - Does not include partial notes (they are converted to headers).
/// - Wraps public notes in [`PublicOutputNote`] which enforces size limits.
/// - Contains only the minimal information needed for verification.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputNote {
    /// A public note with full details, size-validated.
    Public(PublicOutputNote),
    /// A private note with a header and attachments.
    Private(PrivateOutputNote),
}

impl OutputNote {
    /// Unique note identifier.
    ///
    /// This value commits to the note details and metadata.
    pub fn id(&self) -> NoteId {
        match self {
            Self::Public(note) => note.id(),
            Self::Private(header) => header.id(),
        }
    }

    /// Returns the note's [`NoteHeader`].
    pub fn header(&self) -> &NoteHeader {
        match self {
            Self::Public(note) => note.header(),
            Self::Private(note) => note.header(),
        }
    }

    /// Returns the commitment to the note's details, excluding metadata.
    pub fn details_commitment(&self) -> NoteDetailsCommitment {
        match self {
            Self::Public(note) => note.details_commitment(),
            Self::Private(header) => header.details_commitment(),
        }
    }

    /// The assets contained in the note, if available.
    ///
    /// Returns `Some` for public notes, `None` for private notes.
    pub fn assets(&self) -> Option<&NoteAssets> {
        match self {
            Self::Public(note) => Some(note.assets()),
            Self::Private(_) => None,
        }
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.header().metadata()
    }

    /// Returns the recipient of the public note, if this is a public note.
    pub fn recipient(&self) -> Option<&NoteRecipient> {
        match self {
            Self::Public(note) => Some(note.recipient()),
            Self::Private(_) => None,
        }
    }
}

// CONVERSIONS
// ------------------------------------------------------------------------------------------------

impl<'note> From<&'note OutputNote> for &'note NoteHeader {
    fn from(note: &'note OutputNote) -> Self {
        note.header()
    }
}

impl From<&OutputNote> for NoteId {
    fn from(note: &OutputNote) -> Self {
        note.id()
    }
}

// PUBLIC OUTPUT NOTE
// ================================================================================================

/// A public output note with enforced size limits.
///
/// This struct wraps a [`Note`] and guarantees that:
/// - The note is public (not private).
/// - The serialized size does not exceed [`NOTE_MAX_SIZE`].
///
/// This type is used in [`OutputNote::Public`] to ensure that all public notes in proven
/// transactions meet the protocol's size requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicOutputNote(Note);

impl PublicOutputNote {
    /// Creates a new [`PublicOutputNote`] from the given note.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The note is private.
    /// - The serialized size exceeds [`NOTE_MAX_SIZE`].
    pub fn new(mut note: Note) -> Result<Self, OutputNoteError> {
        // Ensure the note is public
        if note.metadata().is_private() {
            return Err(OutputNoteError::NoteIsPrivate(note.id()));
        }

        // Remove debug info from the note script (if any)
        note.clear_debug_info();

        // Check the size limit after stripping decorators
        let note_size = note.get_size_hint();
        if note_size > NOTE_MAX_SIZE as usize {
            return Err(OutputNoteError::NoteSizeLimitExceeded { note_id: note.id(), note_size });
        }

        Ok(Self(note))
    }

    /// Returns the unique identifier of this note.
    pub fn id(&self) -> NoteId {
        self.0.id()
    }

    /// Returns the commitment to the note's details, excluding metadata.
    pub fn details_commitment(&self) -> NoteDetailsCommitment {
        self.0.details_commitment()
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.0.metadata()
    }

    /// Returns the note's assets.
    pub fn assets(&self) -> &NoteAssets {
        self.0.assets()
    }

    /// Returns the note's recipient.
    pub fn recipient(&self) -> &NoteRecipient {
        self.0.recipient()
    }

    /// Returns the note's header.
    pub fn header(&self) -> &NoteHeader {
        self.0.header()
    }

    /// Returns a reference to the underlying note.
    pub fn as_note(&self) -> &Note {
        &self.0
    }

    /// Consumes this wrapper and returns the underlying note.
    pub fn into_note(self) -> Note {
        self.0
    }
}

// PRIVATE NOTE HEADER
// ================================================================================================

/// A [`NoteHeader`] of a private note, along with its public attachments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateOutputNote {
    header: NoteHeader,
    attachments: NoteAttachments,
}

impl PrivateOutputNote {
    /// Creates a new [`PrivateOutputNote`] from the given note header and attachments.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The provided header is for a public note.
    /// - The attachment headers in the provided header do not match the provided attachments.
    /// - The attachments commitment in the provided header does not match the provided attachments.
    pub fn new(header: NoteHeader, attachments: NoteAttachments) -> Result<Self, OutputNoteError> {
        if header.metadata().is_public() {
            return Err(OutputNoteError::NoteIsPublic(header.id()));
        }

        if header.metadata().attachment_headers() != &attachments.to_headers() {
            return Err(OutputNoteError::AttachmentHeadersMismatch(header.id()));
        }

        if header.metadata().attachments_commitment() != attachments.to_commitment() {
            return Err(OutputNoteError::AttachmentsCommitmentMismatch(header.id()));
        }

        Ok(Self { header, attachments })
    }

    /// Returns the note's identifier.
    ///
    /// The [NoteId] commits to both note details and metadata.
    pub fn id(&self) -> NoteId {
        self.header.id()
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.header.metadata()
    }

    /// Returns the note's attachments.
    pub fn attachments(&self) -> &NoteAttachments {
        &self.attachments
    }

    /// Returns the commitment to the note's details, excluding metadata.
    pub fn details_commitment(&self) -> NoteDetailsCommitment {
        self.header.details_commitment()
    }

    /// Returns a reference to the underlying note header.
    pub fn header(&self) -> &NoteHeader {
        &self.header
    }

    /// Consumes this wrapper and returns the underlying note header.
    pub fn into_header(self) -> NoteHeader {
        self.header
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::RawOutputNote;
    use crate::Word;
    use crate::note::Note;

    #[test]
    fn output_note_exposes_its_header() {
        let note = Note::mock_noop(Word::from([1_u32, 2, 3, 4]));
        let output_note = RawOutputNote::Full(note.clone()).into_output_note().unwrap();

        assert_eq!(output_note.header(), note.header());
    }
}
