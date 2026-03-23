use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::constants::NOTE_MAX_SIZE;
use crate::errors::{OutputNoteError, TransactionOutputError};
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
    /// The commitment is computed as a sequential hash of (note ID, metadata) tuples for the notes
    /// created in a transaction.
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

impl<N> IntoIterator for OutputNoteCollection<N> {
    type Item = N;

    type IntoIter = alloc::vec::IntoIter<N>;

    fn into_iter(self) -> Self::IntoIter {
        self.notes.into_iter()
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl<N: Serializable> Serializable for OutputNoteCollection<N> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // assert is OK here because we enforce max number of notes in the constructor
        assert!(self.notes.len() <= u16::MAX.into());
        target.write_u16(self.notes.len() as u16);
        target.write_many(&self.notes);
    }
}

impl<N> Deserializable for OutputNoteCollection<N>
where
    N: Deserializable,
    for<'a> &'a NoteHeader: From<&'a N>,
    for<'a> NoteId: From<&'a N>,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_notes = source.read_u16()?;
        let notes = source.read_many_iter::<N>(num_notes.into())?.collect::<Result<_, _>>()?;
        Self::new(notes).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
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
    const FULL: u8 = 0;
    const PARTIAL: u8 = 1;

    /// The assets contained in the note.
    pub fn assets(&self) -> &NoteAssets {
        match self {
            Self::Full(note) => note.assets(),
            Self::Partial(note) => note.assets(),
        }
    }

    /// Unique note identifier.
    ///
    /// This value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        match self {
            Self::Full(note) => note.id(),
            Self::Partial(note) => note.id(),
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
                let note_id = note.id();
                let (_, metadata, _) = note.into_parts();
                let note_header = NoteHeader::new(note_id, metadata);
                Ok(OutputNote::Private(PrivateNoteHeader::new(note_header)?))
            },
            Self::Full(note) => Ok(OutputNote::Public(PublicOutputNote::new(note)?)),
            Self::Partial(note) => {
                let (_, header) = note.into_parts();
                Ok(OutputNote::Private(PrivateNoteHeader::new(header)?))
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

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
    pub fn commitment(&self) -> Word {
        compute_note_commitment(self.id(), self.metadata())
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

impl Serializable for RawOutputNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Full(note) => {
                target.write(Self::FULL);
                target.write(note);
            },
            Self::Partial(note) => {
                target.write(Self::PARTIAL);
                target.write(note);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        // Serialized size of the enum tag.
        let tag_size = 0u8.get_size_hint();

        match self {
            Self::Full(note) => tag_size + note.get_size_hint(),
            Self::Partial(note) => tag_size + note.get_size_hint(),
        }
    }
}

impl Deserializable for RawOutputNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::FULL => Ok(Self::Full(Note::read_from(source)?)),
            Self::PARTIAL => Ok(Self::Partial(PartialNote::read_from(source)?)),
            v => Err(DeserializationError::InvalidValue(format!("invalid output note type: {v}"))),
        }
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
    /// A note private header (for private notes).
    Private(PrivateNoteHeader),
}

impl OutputNote {
    const PUBLIC: u8 = 0;
    const PRIVATE: u8 = 1;

    /// Unique note identifier.
    ///
    /// This value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        match self {
            Self::Public(note) => note.id(),
            Self::Private(header) => header.id(),
        }
    }

    /// Note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        match self {
            Self::Public(note) => note.metadata(),
            Self::Private(header) => header.metadata(),
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

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
    pub fn to_commitment(&self) -> Word {
        compute_note_commitment(self.id(), self.metadata())
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
    fn from(value: &'note OutputNote) -> Self {
        match value {
            OutputNote::Public(note) => note.header(),
            OutputNote::Private(header) => &header.0,
        }
    }
}

impl From<&OutputNote> for NoteId {
    fn from(value: &OutputNote) -> Self {
        value.id()
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for OutputNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Public(note) => {
                target.write(Self::PUBLIC);
                target.write(note);
            },
            Self::Private(header) => {
                target.write(Self::PRIVATE);
                target.write(header);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let tag_size = 0u8.get_size_hint();
        match self {
            Self::Public(note) => tag_size + note.get_size_hint(),
            Self::Private(header) => tag_size + header.get_size_hint(),
        }
    }
}

impl Deserializable for OutputNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::PUBLIC => Ok(Self::Public(PublicOutputNote::read_from(source)?)),
            Self::PRIVATE => Ok(Self::Private(PrivateNoteHeader::read_from(source)?)),
            v => Err(DeserializationError::InvalidValue(format!(
                "invalid proven output note type: {v}"
            ))),
        }
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

        // Strip decorators from the note script
        note.minify_script();

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

impl Serializable for PublicOutputNote {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for PublicOutputNote {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note = Note::read_from(source)?;
        Self::new(note).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// PRIVATE NOTE HEADER
// ================================================================================================

/// A [NoteHeader] of a private note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateNoteHeader(NoteHeader);

impl PrivateNoteHeader {
    /// Creates a new [`PrivateNoteHeader`] from the given note header.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The provided header is for a public note.
    pub fn new(header: NoteHeader) -> Result<Self, OutputNoteError> {
        if !header.metadata().is_private() {
            return Err(OutputNoteError::NoteIsPublic(header.id()));
        }

        Ok(Self(header))
    }

    /// Returns the note's identifier.
    ///
    /// The [NoteId] value is both an unique identifier and a commitment to the note.
    pub fn id(&self) -> NoteId {
        self.0.id()
    }

    /// Returns the note's metadata.
    pub fn metadata(&self) -> &NoteMetadata {
        self.0.metadata()
    }

    /// Consumes self and returns the note header's metadata.
    pub fn into_metadata(self) -> NoteMetadata {
        self.0.into_metadata()
    }

    /// Returns a commitment to the note and its metadata.
    ///
    /// > hash(NOTE_ID || NOTE_METADATA_COMMITMENT)
    ///
    /// This value is used primarily for authenticating notes consumed when they are consumed
    /// in a transaction.
    pub fn commitment(&self) -> Word {
        self.0.to_commitment()
    }

    /// Returns a reference to the underlying note header.
    pub fn as_header(&self) -> &NoteHeader {
        &self.0
    }

    /// Consumes this wrapper and returns the underlying note header.
    pub fn into_header(self) -> NoteHeader {
        self.0
    }
}

impl Serializable for PrivateNoteHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for PrivateNoteHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = NoteHeader::read_from(source)?;
        Self::new(header).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
