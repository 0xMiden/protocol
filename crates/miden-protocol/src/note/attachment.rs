use alloc::string::ToString;
use alloc::vec::Vec;

use miden_core::WORD_SIZE;

use crate::crypto::SequentialCommit;
use crate::errors::NoteError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

// NOTE ATTACHMENT
// ================================================================================================

/// The optional attachment for a [`Note`](super::Note).
///
/// An attachment is a _public_ extension to a note's [`NoteMetadata`](super::NoteMetadata).
///
/// Example use cases:
/// - Communicate the [`NoteDetails`](super::NoteDetails) of a private note in encrypted form.
/// - In the context of network transactions, encode the ID of the network account that should
///   consume the note.
/// - Communicate details to the receiver of a _private_ note to allow deriving the
///   [`NoteDetails`](super::NoteDetails) of that note. For instance, the payback note of a partial
///   swap note can be private, but the receiver needs to know additional details to fully derive
///   the content of the payback note. They can neither fetch those details from the network, since
///   the note is private, nor is a side-channel available. The note attachment can encode those
///   details.
///
/// These use cases require different amounts of data, e.g. an account ID takes up just two felts
/// while the details of an encrypted note require many felts. To accommodate these cases, both a
/// computationally efficient [`NoteAttachmentContent::Word`] as well as a more flexible
/// [`NoteAttachmentContent::Array`] variant are available. See the type's docs for more
/// details.
///
/// Next to the content, a note attachment can optionally specify a [`NoteAttachmentScheme`]. This
/// allows a note attachment to describe itself. For example, a network account target attachment
/// can be identified by a standardized type. For cases when the attachment scheme is known from
/// content or typing is otherwise undesirable, [`NoteAttachmentScheme::none`] can be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAttachment {
    attachment_scheme: NoteAttachmentScheme,
    content: NoteAttachmentContent,
}

impl NoteAttachment {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachment`] from a user-defined scheme and the provided content.
    pub fn new(attachment_scheme: NoteAttachmentScheme, content: NoteAttachmentContent) -> Self {
        Self { attachment_scheme, content }
    }

    /// Creates a new note attachment with content [`NoteAttachmentContent::Word`] from the provided
    /// word.
    pub fn new_word(attachment_scheme: NoteAttachmentScheme, word: Word) -> Self {
        Self {
            attachment_scheme,
            content: NoteAttachmentContent::new_word(word),
        }
    }

    /// Creates a new note attachment with content [`NoteAttachmentContent::Array`] from the
    /// provided set of elements.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of elements exceeds [`NoteAttachmentArray::MAX_NUM_ELEMENTS`].
    /// - The number of elements is less than [`NoteAttachmentArray::MIN_NUM_ELEMENTS`].
    pub fn new_array(
        attachment_scheme: NoteAttachmentScheme,
        elements: Vec<Felt>,
    ) -> Result<Self, NoteError> {
        NoteAttachmentContent::new_array(elements)
            .map(|content| Self { attachment_scheme, content })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the attachment scheme.
    pub fn attachment_scheme(&self) -> NoteAttachmentScheme {
        self.attachment_scheme
    }

    /// Returns a reference to the attachment content.
    pub fn content(&self) -> &NoteAttachmentContent {
        &self.content
    }

    /// Returns the size of this attachment in words.
    ///
    /// - `1` indicates a single word attachment ([`NoteAttachmentContent::Word`]).
    /// - `> 1` indicates an array attachment ([`NoteAttachmentContent::Array`]).
    pub fn num_words(&self) -> u8 {
        self.content.num_words()
    }
}

impl Serializable for NoteAttachment {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.attachment_scheme().write_into(target);
        self.content().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.attachment_scheme().get_size_hint() + self.content().get_size_hint()
    }
}

impl Deserializable for NoteAttachment {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let attachment_scheme = NoteAttachmentScheme::read_from(source)?;
        let content = NoteAttachmentContent::read_from(source)?;

        Ok(Self::new(attachment_scheme, content))
    }
}

// NOTE ATTACHMENT CONTENT
// ================================================================================================

/// The content of a [`NoteAttachment`].
///
/// When a single [`Word`] has sufficient space, [`NoteAttachmentContent::Word`] should be used.
///
/// If the space of a [`Word`] is insufficient, the more flexible
/// [`NoteAttachmentContent::Array`] variant can be used. It contains a set of field elements
/// where only their sequential hash is encoded into the [`NoteMetadata`](super::NoteMetadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteAttachmentContent {
    /// A note attachment consisting of a single [`Word`].
    Word(Word),

    /// A note attachment consisting of the commitment to a set of felts.
    Array(NoteAttachmentArray),
}

impl NoteAttachmentContent {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentContent::Word`] containing an empty word.
    pub fn empty_word() -> Self {
        Self::Word(Word::empty())
    }

    /// Creates a new [`NoteAttachmentContent::Word`] from the provided word.
    pub fn new_word(word: Word) -> Self {
        Self::Word(word)
    }

    /// Creates a new [`NoteAttachmentContent::Array`] from the provided elements.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of elements exceeds [`NoteAttachmentArray::MAX_NUM_ELEMENTS`].
    /// - The number of elements is less than [`NoteAttachmentArray::MIN_NUM_ELEMENTS`].
    pub fn new_array(elements: Vec<Felt>) -> Result<Self, NoteError> {
        NoteAttachmentArray::new(elements).map(Self::from)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns `true` if the content is `Word`, `false` otherwise.
    pub fn is_word(&self) -> bool {
        matches!(self, NoteAttachmentContent::Word(_))
    }

    /// Returns `true` if the content is `Array`, `false` otherwise.
    pub fn is_array(&self) -> bool {
        matches!(self, NoteAttachmentContent::Array(_))
    }

    /// Returns the size of this attachment content in words.
    ///
    /// - `1` for [`NoteAttachmentContent::Word`].
    /// - `> 1` for [`NoteAttachmentContent::Array`].
    pub fn word_size(&self) -> u8 {
        match self {
            NoteAttachmentContent::Word(_) => 1,
            NoteAttachmentContent::Array(array) => array.word_size(),
        }
    }

    /// Returns the [`NoteAttachmentContent`] encoded to a [`Word`].
    ///
    /// See the type-level documentation for more details.
    pub fn to_word(&self) -> Word {
        match self {
            NoteAttachmentContent::Word(word) => *word,
            NoteAttachmentContent::Array(attachment_commitment) => {
                attachment_commitment.commitment()
            },
        }
    }
}

impl Serializable for NoteAttachmentContent {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write word_size as discriminant: 1 = Word, >1 = Array.
        self.word_size().write_into(target);

        match self {
            NoteAttachmentContent::Word(word) => {
                word.write_into(target);
            },
            NoteAttachmentContent::Array(arr) => {
                arr.num_elements().write_into(target);
                target.write_many(&arr.elements);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let discriminant_size = core::mem::size_of::<u8>();
        match self {
            NoteAttachmentContent::Word(word) => discriminant_size + word.get_size_hint(),
            NoteAttachmentContent::Array(array) => {
                discriminant_size
                    + array.num_elements().get_size_hint()
                    + array.elements.len() * Felt::ZERO.get_size_hint()
            },
        }
    }
}

impl Deserializable for NoteAttachmentContent {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let word_size = u8::read_from(source)?;

        match word_size {
            0 => Err(DeserializationError::InvalidValue(
                "attachment content word_size must be > 0".into(),
            )),
            1 => {
                let word = Word::read_from(source)?;
                Ok(NoteAttachmentContent::Word(word))
            },
            _ => {
                let num_elements = u16::read_from(source)?;
                let elements =
                    source.read_many_iter(usize::from(num_elements))?.collect::<Result<_, _>>()?;
                Self::new_array(elements)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
            },
        }
    }
}

// NOTE ATTACHMENT ARRAY
// ================================================================================================

/// The type contained in [`NoteAttachmentContent::Array`] that commits to a set of field
/// elements.
///
/// The number of elements must be divisible by [`WORD_SIZE`], i.e. the array must contain only
/// whole words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAttachmentArray {
    elements: Vec<Felt>,
    commitment: Word,
}

impl NoteAttachmentArray {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The minimum number of elements in a note attachment array.
    ///
    /// Array attachments must contain at least 2 words (8 elements) to distinguish them from word
    /// attachments.
    pub const MIN_NUM_ELEMENTS: u8 = (WORD_SIZE as u8) * 2;

    /// The maximum number of elements in a note attachment array.
    ///
    /// Each attachment can be at most [`NoteAttachmentHeader::MAX_SIZE`] words (254), and each
    /// word holds 4 elements, so the maximum number of elements is 254 * 4 = 1016.
    pub const MAX_NUM_ELEMENTS: u16 = NoteAttachmentHeader::MAX_SIZE as u16 * (WORD_SIZE as u16);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentArray`] from the provided elements.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of elements is not a multiple of [`WORD_SIZE`].
    /// - The number of elements is less than [`Self::MIN_NUM_ELEMENTS`].
    /// - The number of elements exceeds [`Self::MAX_NUM_ELEMENTS`].
    pub fn new(elements: Vec<Felt>) -> Result<Self, NoteError> {
        if !elements.len().is_multiple_of(WORD_SIZE) {
            return Err(NoteError::NoteAttachmentArrayNotWordAligned(elements.len()));
        }

        if elements.len() < Self::MIN_NUM_ELEMENTS as usize {
            return Err(NoteError::NoteAttachmentArrayTooFewElements(elements.len()));
        }

        if elements.len() > Self::MAX_NUM_ELEMENTS as usize {
            return Err(NoteError::NoteAttachmentArraySizeExceeded(elements.len()));
        }

        let commitment = Hasher::hash_elements(&elements);
        Ok(Self { elements, commitment })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the elements this note attachment commits to.
    pub fn as_slice(&self) -> &[Felt] {
        &self.elements
    }

    /// Returns the number of elements this note attachment commits to.
    pub fn num_elements(&self) -> u16 {
        u16::try_from(self.elements.len()).expect("type should enforce that size fits in u16")
    }

    /// Returns the number of elements this note attachment commits to.
    pub fn word_size(&self) -> u8 {
        // SAFETY:
        // - num elements is at most 1016 and 1016/4 = 254, so it fits in a u8
        // - constructor checks that num elements is a multiple of WORD_SIZE, so we don't need to
        //   check the remainder
        u8::try_from(self.elements.len() / WORD_SIZE).expect("word size shoult fit in u8")
    }

    /// Returns the commitment over the contained field elements.
    pub fn commitment(&self) -> Word {
        self.commitment
    }
}

impl SequentialCommit for NoteAttachmentArray {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        self.elements.clone()
    }

    fn to_commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl From<NoteAttachmentArray> for NoteAttachmentContent {
    fn from(array: NoteAttachmentArray) -> Self {
        NoteAttachmentContent::Array(array)
    }
}

// NOTE ATTACHMENT SCHEME
// ================================================================================================

/// The user-defined type of a [`NoteAttachment`].
///
/// A note attachment scheme is an arbitrary 16-bit unsigned integer (max [`Self::MAX`]).
///
/// Value `0` is reserved to signal that the scheme is none or absent. Whenever the kind of
/// attachment is not standardized or interoperability is unimportant, this none value can be
/// used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteAttachmentScheme(u16);

impl NoteAttachmentScheme {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The reserved value to signal an absent note attachment scheme.
    const NONE: u16 = 0;

    /// The maximum value for a note attachment scheme.
    ///
    /// Limited to `2^16 - 2 = 65534` to ensure the felt encoding remains valid when four
    /// schemes are packed into a single felt in the note metadata. Limiting schemes to this value
    /// means at least one bit is always unset which ensures felt validity.
    pub const MAX: NoteAttachmentScheme = NoteAttachmentScheme(65534);

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentScheme`] from a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if `attachment_scheme` exceeds [`Self::MAX`].
    pub fn new(attachment_scheme: u16) -> Result<Self, NoteError> {
        if attachment_scheme > Self::MAX.as_u16() {
            return Err(NoteError::NoteAttachmentSchemeExceeded(attachment_scheme as u32));
        }
        Ok(Self(attachment_scheme))
    }

    /// Returns the [`NoteAttachmentScheme`] that signals the absence of an attachment scheme.
    pub const fn none() -> Self {
        Self(Self::NONE)
    }

    /// Returns `true` if the attachment scheme is the reserved value that signals an absent scheme,
    /// `false` otherwise.
    pub const fn is_none(&self) -> bool {
        self.0 == Self::NONE
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the note attachment scheme as a u16.
    pub const fn as_u16(&self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for NoteAttachmentScheme {
    type Error = NoteError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Default for NoteAttachmentScheme {
    /// Returns [`NoteAttachmentScheme::none`].
    fn default() -> Self {
        Self::none()
    }
}

impl core::fmt::Display for NoteAttachmentScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl Serializable for NoteAttachmentScheme {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_u16().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u16>()
    }
}

impl Deserializable for NoteAttachmentScheme {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let value = u16::read_from(source)?;
        Self::try_from(value).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// NOTE ATTACHMENT HEADER
// ================================================================================================

/// The header metadata for a single note attachment.
///
/// Contains the scheme and word size of an attachment, without the actual content data.
/// The kind of attachment is inferred from the size:
/// - `size == 0`: absent (no attachment)
/// - `size == 1`: word attachment (a single [`Word`])
/// - `size > 1`: array attachment (a commitment to a set of felts)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteAttachmentHeader {
    scheme: NoteAttachmentScheme,
    word_size: u8,
}

impl NoteAttachmentHeader {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum attachment size in words.
    ///
    /// Limited to 254 to ensure the size fits into a u8 and the felt encoding remains valid
    /// when four sizes are packed into a single felt in the note metadata.
    pub const MAX_SIZE: u8 = 254;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentHeader`].
    ///
    /// # Errors
    ///
    /// Returns an error if `size` exceeds [`Self::MAX_SIZE`].
    pub fn new(scheme: NoteAttachmentScheme, word_size: u8) -> Result<Self, NoteError> {
        if word_size > Self::MAX_SIZE {
            return Err(NoteError::NoteAttachmentHeaderSizeExceeded(word_size));
        }
        Ok(Self { scheme, word_size })
    }

    /// Returns a header representing the absence of an attachment.
    pub const fn absent() -> Self {
        Self {
            scheme: NoteAttachmentScheme::none(),
            word_size: 0,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the attachment scheme.
    pub const fn scheme(&self) -> NoteAttachmentScheme {
        self.scheme
    }

    /// Returns the attachment size in words.
    pub const fn word_size(&self) -> u8 {
        self.word_size
    }

    /// Returns `true` if this header represents an absent attachment, `false` otherwise.
    pub const fn is_absent(&self) -> bool {
        self.word_size == 0 && self.scheme.is_none()
    }
}

impl Default for NoteAttachmentHeader {
    fn default() -> Self {
        Self::absent()
    }
}

impl Serializable for NoteAttachmentHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.scheme.write_into(target);
        self.word_size.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.scheme.get_size_hint() + core::mem::size_of::<u8>()
    }
}

impl Deserializable for NoteAttachmentHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let scheme = NoteAttachmentScheme::read_from(source)?;
        let size = u8::read_from(source)?;
        Self::new(scheme, size).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// NOTE ATTACHMENTS
// ================================================================================================

/// A collection of note attachments.
///
/// Notes can have up to [`Self::MAX_COUNT`] attachments.
///
/// The commitment to the attachments is defined as:
/// - 0 attachments: `EMPTY_WORD`
/// - 1+ attachments: sequential hash over all attachment words
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAttachments {
    attachments: Vec<NoteAttachment>,
    commitment: Word,
}

impl NoteAttachments {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of attachments per note.
    pub const MAX_COUNT: usize = 4;

    /// The maximum total number of elements across all attachments in a note.
    ///
    /// Each element holds roughly 8 bytes of data and so this allows for a maximum of
    /// 512 * 32 = 2^14 = 16384 bytes.
    pub const MAX_NUM_WORDS: u16 = 512;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new empty [`NoteAttachments`] collection.
    pub fn empty() -> Self {
        Self {
            attachments: Vec::new(),
            commitment: Word::empty(),
        }
    }

    /// Creates a [`NoteAttachments`] from a vector of attachments.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of attachments exceeds [`Self::MAX_COUNT`].
    /// - The total number of words across all attachments exceeds [`Self::MAX_NUM_WORDS`].
    pub fn new(attachments: Vec<NoteAttachment>) -> Result<Self, NoteError> {
        if attachments.len() > Self::MAX_COUNT {
            return Err(NoteError::TooManyAttachments(attachments.len()));
        }

        let total_num_words = attachments
            .iter()
            .map(|attachment| attachment.word_size() as usize)
            .sum::<usize>();

        if total_num_words > Self::MAX_NUM_WORDS as usize {
            return Err(NoteError::TooManyAttachmentElements(total_num_words));
        }

        let commitment = compute_commitment(&attachments);

        Ok(Self { attachments, commitment })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the attachment at the given index, if it exists.
    pub fn get(&self, index: usize) -> Option<&NoteAttachment> {
        self.attachments.get(index)
    }

    /// Returns the number of attachments.
    pub fn num_attachments(&self) -> u8 {
        u8::try_from(self.attachments.len())
            .expect("constructor should ensure num attachment fits in u8")
    }

    /// Returns `true` if there are no attachments.
    pub fn is_empty(&self) -> bool {
        self.attachments.is_empty()
    }

    /// Returns an iterator over the attachments.
    pub fn iter(&self) -> impl Iterator<Item = &NoteAttachment> {
        self.attachments.iter()
    }

    /// Returns the cached commitment over the contained attachments.
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// Returns the attachment headers for all attachment slots.
    ///
    /// Returns a fixed-size array of [`Self::MAX_COUNT`] headers. Unused slots are filled with
    /// [`NoteAttachmentHeader::absent`].
    pub fn to_headers(&self) -> [NoteAttachmentHeader; Self::MAX_COUNT] {
        let mut headers = [NoteAttachmentHeader::absent(); Self::MAX_COUNT];
        for (i, attachment) in self.attachments.iter().enumerate() {
            headers[i] =
                NoteAttachmentHeader::new(attachment.attachment_scheme(), attachment.word_size())
                    .expect(
                        "attachment word_size should not exceed NoteAttachmentHeader::MAX_SIZE",
                    );
        }
        headers
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the inner vector of attachments.
    pub fn into_vec(self) -> Vec<NoteAttachment> {
        self.attachments
    }
}

impl Default for NoteAttachments {
    fn default() -> Self {
        Self::empty()
    }
}

impl SequentialCommit for NoteAttachments {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        attachments_to_elements(&self.attachments)
    }

    fn to_commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

/// Collects all attachment data into a flat vector of field elements.
fn attachments_to_elements(attachments: &[NoteAttachment]) -> Vec<Felt> {
    let mut elements = Vec::new();
    for attachment in attachments {
        match attachment.content() {
            NoteAttachmentContent::Word(word) => {
                elements.extend_from_slice(word.as_elements());
            },
            NoteAttachmentContent::Array(arr) => {
                elements.extend_from_slice(arr.as_slice());
            },
        }
    }
    elements
}

/// Collects all attachment words into a flat vector of field elements.
///
/// Each attachment contributes exactly one word (4 felts): the raw content for word attachments,
/// or the commitment for array attachments.
fn attachments_to_words(attachments: &[NoteAttachment]) -> Vec<Felt> {
    let mut elements = Vec::with_capacity(attachments.len() * WORD_SIZE);
    for attachment in attachments {
        elements.extend_from_slice(attachment.content().to_word().as_elements());
    }
    elements
}

/// Computes the commitment over a slice of attachments.
fn compute_commitment(attachments: &[NoteAttachment]) -> Word {
    if attachments.is_empty() {
        Word::empty()
    } else {
        Hasher::hash_elements(&attachments_to_words(attachments))
    }
}

impl From<NoteAttachment> for NoteAttachments {
    fn from(attachment: NoteAttachment) -> Self {
        Self::new(vec![attachment]).expect("one attachment does not exceed the max of four")
    }
}

impl Serializable for NoteAttachments {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.num_attachments().write_into(target);
        target.write_many(&self.attachments);
    }

    fn get_size_hint(&self) -> usize {
        self.num_attachments().get_size_hint()
            + self.iter().map(NoteAttachment::get_size_hint).sum::<usize>()
    }
}

impl Deserializable for NoteAttachments {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_attachments = u8::read_from(source)? as usize;
        let attachments = source
            .read_many_iter::<NoteAttachment>(num_attachments)?
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(attachments).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[rstest::rstest]
    #[case::attachment_word(NoteAttachment::new_word(NoteAttachmentScheme::new(1)?, Word::from([3, 4, 5, 6u32])))]
    #[case::attachment_array(NoteAttachment::new_array(
        NoteAttachmentScheme::MAX,
        vec![Felt::new(1); 8],
    )?)]
    #[test]
    fn note_attachment_serde(#[case] attachment: NoteAttachment) -> anyhow::Result<()> {
        assert_eq!(attachment, NoteAttachment::read_from_bytes(&attachment.to_bytes())?);
        Ok(())
    }

    #[test]
    fn note_attachment_array_fails_on_too_many_elements() -> anyhow::Result<()> {
        let too_many_elements = (NoteAttachmentArray::MAX_NUM_ELEMENTS as usize) + 4;
        let elements = vec![Felt::from(1u32); too_many_elements];
        let err = NoteAttachmentArray::new(elements).unwrap_err();

        assert_matches!(err, NoteError::NoteAttachmentArraySizeExceeded(len) => {
            len == too_many_elements
        });

        Ok(())
    }

    #[test]
    fn note_attachment_array_fails_on_too_few_elements() {
        let elements = vec![Felt::from(1u32); 4];
        let err = NoteAttachmentArray::new(elements).unwrap_err();
        // Arrays must have at least MIN_NUM_ELEMENTS (8) to distinguish from word attachments.
        assert_matches!(err, NoteError::NoteAttachmentArrayTooFewElements(4));
    }

    #[test]
    fn note_attachment_array_fails_on_non_word_aligned_length() {
        let elements = vec![Felt::from(1u32); 9];
        let err = NoteAttachmentArray::new(elements).unwrap_err();
        assert_matches!(err, NoteError::NoteAttachmentArrayNotWordAligned(9));
    }

    #[test]
    fn note_attachment_scheme_max_is_valid() {
        let scheme = NoteAttachmentScheme::MAX;
        assert_eq!(scheme.as_u16(), 65534);
    }

    #[test]
    fn note_attachment_scheme_exceeding_max_fails() {
        let err = NoteAttachmentScheme::new(u16::MAX).unwrap_err();
        assert_matches!(err, NoteError::NoteAttachmentSchemeExceeded(_));
    }

    #[test]
    fn note_attachment_header_serde() -> anyhow::Result<()> {
        let header = NoteAttachmentHeader::new(NoteAttachmentScheme::new(42)?, 10)?;
        let deserialized = NoteAttachmentHeader::read_from_bytes(&header.to_bytes())?;
        assert_eq!(header, deserialized);
        Ok(())
    }

    #[test]
    fn note_attachment_header_absent() {
        let header = NoteAttachmentHeader::absent();
        assert!(header.is_absent());
        assert_eq!(header.word_size(), 0);
        assert!(header.scheme().is_none());
    }

    #[test]
    fn note_attachments_up_to_max() -> anyhow::Result<()> {
        let scheme = NoteAttachmentScheme::new(1)?;
        let attachment = NoteAttachment::new_word(scheme, Word::from([1, 2, 3, 4u32]));
        let attachments = NoteAttachments::new(vec![attachment; NoteAttachments::MAX_COUNT])?;
        assert_eq!(attachments.num_attachments() as usize, NoteAttachments::MAX_COUNT);

        // Exceeding MAX_COUNT should fail.
        let err =
            NoteAttachments::new(vec![
                NoteAttachment::new_word(scheme, Word::from([1, 2, 3, 4u32]));
                NoteAttachments::MAX_COUNT + 1
            ])
            .unwrap_err();
        assert_matches!(err, NoteError::TooManyAttachments(5));

        Ok(())
    }

    #[test]
    fn note_attachments_serde() -> anyhow::Result<()> {
        let attachments = NoteAttachments::new(vec![
            NoteAttachment::new_word(NoteAttachmentScheme::new(1)?, Word::from([1, 2, 3, 4u32])),
            NoteAttachment::new_array(NoteAttachmentScheme::new(100)?, vec![Felt::new(1); 8])?,
        ])?;

        let deserialized = NoteAttachments::read_from_bytes(&attachments.to_bytes())?;
        assert_eq!(attachments, deserialized);

        Ok(())
    }

    #[test]
    fn note_attachments_commitment_empty() {
        let attachments = NoteAttachments::empty();
        assert_eq!(attachments.commitment(), Word::empty());
    }

    #[test]
    fn note_attachments_commitment_single_word() -> anyhow::Result<()> {
        let word = Word::from([10, 20, 30, 40u32]);
        let attachments = NoteAttachments::new(vec![NoteAttachment::new_word(
            NoteAttachmentScheme::new(1)?,
            word,
        )])?;
        // Single word attachment: commitment is the hash of the word.
        assert_eq!(attachments.commitment(), Hasher::hash_elements(word.as_elements()));

        Ok(())
    }

    #[test]
    fn note_attachments_to_headers() -> anyhow::Result<()> {
        let attachments = NoteAttachments::new(vec![
            NoteAttachment::new_word(NoteAttachmentScheme::new(42)?, Word::from([1, 2, 3, 4u32])),
            NoteAttachment::new_array(NoteAttachmentScheme::new(100)?, vec![Felt::new(1); 8])?,
        ])?;

        let headers = attachments.to_headers();
        assert_eq!(headers[0].scheme(), NoteAttachmentScheme::new(42)?);
        assert_eq!(headers[0].word_size(), 1);
        assert_eq!(headers[1].scheme(), NoteAttachmentScheme::new(100)?);
        assert_eq!(headers[1].word_size(), 2); // 8 felts = 2 words
        assert!(headers[2].is_absent());
        assert!(headers[3].is_absent());

        Ok(())
    }

    #[test]
    fn note_attachments_into_vec() -> anyhow::Result<()> {
        let word_att =
            NoteAttachment::new_word(NoteAttachmentScheme::new(1)?, Word::from([1, 2, 3, 4u32]));
        let attachments = NoteAttachments::new(vec![word_att.clone()])?;
        let vec = attachments.into_vec();
        assert_eq!(vec, vec![word_att]);

        Ok(())
    }

    #[test]
    fn note_attachment_word_size() {
        // Word => 1
        let word = NoteAttachmentContent::new_word(Word::from([1, 2, 3, 4u32]));
        assert_eq!(word.word_size(), 1);

        // Array with 8 elements => 8/4 = 2
        let array = NoteAttachmentContent::new_array(vec![Felt::new(1); 8]).unwrap();
        assert_eq!(array.word_size(), 2);

        // Array with 12 elements => 12/4 = 3
        let array = NoteAttachmentContent::new_array(vec![Felt::new(1); 12]).unwrap();
        assert_eq!(array.word_size(), 3);
    }
}
