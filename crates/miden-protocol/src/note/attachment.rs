use alloc::string::ToString;
use alloc::vec::Vec;

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
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of words in an attachment.
    ///
    /// Each element holds roughly 8 bytes of data and so this allows for a maximum of
    /// 256 * 32 = 2^13 = 8192 bytes.
    pub const MAX_NUM_WORDS: u16 = 256;

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
    /// provided words.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of words is less than [`NoteAttachmentArray::MIN_NUM_WORDS`].
    /// - The number of words exceeds [`NoteAttachment::MAX_NUM_WORDS`].
    pub fn new_array(
        attachment_scheme: NoteAttachmentScheme,
        words: Vec<Word>,
    ) -> Result<Self, NoteError> {
        NoteAttachmentContent::new_array(words).map(|content| Self { attachment_scheme, content })
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

    /// Computes the commitment of the attachment.
    pub fn to_commitment(&self) -> Word {
        self.content().to_commitment()
    }

    /// Returns the size of this attachment in words.
    ///
    /// - `1` indicates a single word attachment ([`NoteAttachmentContent::Word`]).
    /// - `> 1` indicates an array attachment ([`NoteAttachmentContent::Array`]).
    pub fn num_words(&self) -> u16 {
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

    /// Creates a new [`NoteAttachmentContent::Word`] from the provided word.
    pub fn new_word(word: Word) -> Self {
        Self::Word(word)
    }

    /// Creates a new [`NoteAttachmentContent::Array`] from the provided words.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of words is less than [`NoteAttachmentArray::MIN_NUM_WORDS`].
    /// - The number of words exceeds [`NoteAttachment::MAX_NUM_WORDS`].
    pub fn new_array(words: Vec<Word>) -> Result<Self, NoteError> {
        NoteAttachmentArray::new(words).map(Self::from)
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
    pub fn num_words(&self) -> u16 {
        match self {
            NoteAttachmentContent::Word(_) => 1,
            NoteAttachmentContent::Array(array) => array.num_words(),
        }
    }

    /// Returns the raw elements of this attachment content.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns the sequential commitment over the content's elements.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl Serializable for NoteAttachmentContent {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Subtract 1 from num words so we can serialize it as a u8.
        let num_words_minus_1 =
            u8::try_from(self.num_words().checked_sub(1).expect("num_words should be at least 1"))
                .expect("num_words - 1 should fit in u8");
        num_words_minus_1.write_into(target);

        match self {
            NoteAttachmentContent::Word(word) => {
                word.write_into(target);
            },
            NoteAttachmentContent::Array(array) => {
                target.write_many(array.as_words());
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        let discriminant_size = core::mem::size_of::<u8>();
        match self {
            NoteAttachmentContent::Word(word) => discriminant_size + word.get_size_hint(),
            NoteAttachmentContent::Array(array) => {
                discriminant_size + usize::from(array.num_words()) * Word::empty().get_size_hint()
            },
        }
    }
}

impl Deserializable for NoteAttachmentContent {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Add one to the serialized num words to get the original.
        let num_words_minus_1 = u8::read_from(source)?;
        let num_words = u16::from(num_words_minus_1) + 1;

        match num_words {
            0 => Err(DeserializationError::InvalidValue(
                "attachment content num_words must be > 0".into(),
            )),
            1 => {
                let word = Word::read_from(source)?;
                Ok(NoteAttachmentContent::Word(word))
            },
            _ => {
                let words: Vec<Word> =
                    source.read_many_iter(num_words as usize)?.collect::<Result<_, _>>()?;
                Self::new_array(words)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
            },
        }
    }
}

impl SequentialCommit for NoteAttachmentContent {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        match self {
            NoteAttachmentContent::Word(word) => word.as_elements().to_vec(),
            NoteAttachmentContent::Array(array) => array.to_elements(),
        }
    }

    fn to_commitment(&self) -> Self::Commitment {
        match self {
            NoteAttachmentContent::Word(word) => Hasher::hash_elements(word.as_elements()),
            NoteAttachmentContent::Array(array) => array.commitment(),
        }
    }
}

// NOTE ATTACHMENT ARRAY
// ================================================================================================

/// The type contained in [`NoteAttachmentContent::Array`] that commits to a set of words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAttachmentArray {
    words: Vec<Word>,
    commitment: Word,
}

impl NoteAttachmentArray {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The minimum number of words in a note attachment array.
    ///
    /// Array attachments must contain at least 2 words to distinguish them from word attachments.
    pub const MIN_NUM_WORDS: u8 = 2;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentArray`] from the provided words.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of words is less than [`Self::MIN_NUM_WORDS`].
    /// - The number of words exceeds [`NoteAttachment::MAX_NUM_WORDS`].
    pub fn new(words: Vec<Word>) -> Result<Self, NoteError> {
        if words.len() < Self::MIN_NUM_WORDS as usize {
            return Err(NoteError::NoteAttachmentArrayTooFewWords(words.len()));
        }

        if words.len() > NoteAttachment::MAX_NUM_WORDS as usize {
            return Err(NoteError::NoteAttachmentArrayTooManyWords(words.len()));
        }

        let elements: Vec<Felt> = words.iter().flat_map(Word::as_elements).copied().collect();
        let commitment = Hasher::hash_elements(&elements);
        Ok(Self { words, commitment })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the words this note attachment commits to.
    pub fn as_words(&self) -> &[Word] {
        &self.words
    }

    /// Returns an iterator over the elements this note attachment commits to.
    pub fn as_elements(&self) -> impl Iterator<Item = &Felt> {
        self.words.iter().flat_map(Word::as_elements)
    }

    /// Returns the elements this note attachment commits to.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns the number of words in this note attachment array.
    pub fn num_words(&self) -> u16 {
        // SAFETY: constructor checks that num_words is less than or equal to 256
        u16::try_from(self.words.len()).expect("num words should fit in u16")
    }

    /// Returns the commitment over the contained words.
    pub fn commitment(&self) -> Word {
        self.commitment
    }
}

impl SequentialCommit for NoteAttachmentArray {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        self.as_elements().copied().collect()
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

/// The user-defined scheme of a [`NoteAttachment`].
///
/// A note attachment scheme is an arbitrary 16-bit unsigned integer (max [`Self::MAX`]). It is
/// intended to be used to distinguish one attachment from another, or find a specific attachment in
/// a note's attachments.
///
/// The scheme is purely a hint, and there is no validation with respect to the attachment content.
/// In other words, any scheme can be associated with any attachment conent. Hence, users should
/// always validate the contents of an attachment, just like with
/// [`NoteStorage`](super::NoteStorage).
///
/// Value `0` is reserved to signal that the entire attachment is absent and so it is not a valid
/// scheme.
///
/// Value `1` is reserved to signal that the scheme is none. Whenever the kind of attachment is not
/// standardized or interoperability is unimportant, this none value can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteAttachmentScheme(u16);

impl NoteAttachmentScheme {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The reserved value to signal an absent attachment. This is not a valid attachment scheme.
    const RESERVED: u16 = 0;

    /// The reserved value to signal a `None` note attachment scheme.
    const NONE: u16 = 1;

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
    /// Returns an error if `attachment_scheme` is equal to 0 or exceeds [`Self::MAX`].
    pub fn new(attachment_scheme: u16) -> Result<Self, NoteError> {
        if attachment_scheme == Self::RESERVED {
            return Err(NoteError::NoteAttachmentSchemeZeroReserved);
        }

        if attachment_scheme > Self::MAX.as_u16() {
            return Err(NoteError::NoteAttachmentSchemeExceeded(attachment_scheme as u32));
        }
        Ok(Self(attachment_scheme))
    }

    /// Creates a new [`NoteAttachmentScheme`] from a `u16`.
    ///
    /// # Panics
    ///
    /// Panics if `attachment_scheme` is 0 or exceeds [`Self::MAX`].
    pub const fn new_const(attachment_scheme: u16) -> Self {
        assert!(attachment_scheme != Self::RESERVED, "attachment scheme must not be 0");
        assert!(attachment_scheme <= Self::MAX.as_u16(), "attachment scheme exceeds maximum");
        Self(attachment_scheme)
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
/// Contains the scheme of an attachment, without the actual content data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteAttachmentHeader {
    /// `None` represents an absent note attachment and `Some` a present one.
    scheme: Option<NoteAttachmentScheme>,
}

impl NoteAttachmentHeader {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentHeader`] from a [`NoteAttachmentScheme`].
    pub fn new(scheme: NoteAttachmentScheme) -> Self {
        Self { scheme: Some(scheme) }
    }

    /// Creates a new [`NoteAttachmentHeader`] from a [`NoteAttachmentScheme`].
    pub fn new_maybe(scheme: Option<NoteAttachmentScheme>) -> Self {
        Self { scheme }
    }

    /// Returns a header representing the absence of an attachment.
    pub const fn absent() -> Self {
        Self { scheme: None }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the attachment scheme.
    pub const fn scheme(&self) -> Option<NoteAttachmentScheme> {
        self.scheme
    }

    /// Returns the header encoded as a u16.
    ///
    /// Encodes `None` to 0 using the niche provided by [`NoteAttachmentScheme`].
    pub(super) fn as_u16(&self) -> u16 {
        match self.scheme {
            None => 0,
            Some(scheme) => scheme.as_u16(),
        }
    }

    /// Returns `true` if this header represents an absent attachment, `false` otherwise.
    pub const fn is_absent(&self) -> bool {
        self.scheme.is_none()
    }
}

impl Default for NoteAttachmentHeader {
    fn default() -> Self {
        Self::absent()
    }
}

impl From<NoteAttachmentScheme> for NoteAttachmentHeader {
    fn from(scheme: NoteAttachmentScheme) -> Self {
        NoteAttachmentHeader::new(scheme)
    }
}

impl Serializable for NoteAttachmentHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.scheme.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.scheme.get_size_hint()
    }
}

impl Deserializable for NoteAttachmentHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let scheme = Option::<NoteAttachmentScheme>::read_from(source)?;
        Ok(Self::new_maybe(scheme))
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
/// - 1+ attachments: `hash(ATTACHMENT_0_COMMITMENT || ... || ATTACHMENT_N_COMMITMENT)`, i.e., the
///   sequential hash over the individual attachment commitments.
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
            .map(|attachment| attachment.num_words() as usize)
            .sum::<usize>();

        if total_num_words > Self::MAX_NUM_WORDS as usize {
            return Err(NoteError::NoteAttachmentArrayTooManyWords(total_num_words));
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

    /// Returns the individual commitment of each contained attachment.
    pub fn commitments(&self) -> Vec<Word> {
        self.attachments
            .iter()
            .map(|attachment| attachment.content().to_commitment())
            .collect()
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
            headers[i] = NoteAttachmentHeader::new(attachment.attachment_scheme());
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

/// Collects all attachment commitments into a flat vector of field elements.
fn attachments_to_elements(attachments: &[NoteAttachment]) -> Vec<Felt> {
    let mut elements = Vec::new();
    for commitment in attachments.iter().map(|attachment| attachment.content().to_commitment()) {
        elements.extend_from_slice(commitment.as_elements());
    }
    elements
}

/// Computes the commitment over a slice of attachments.
///
/// The commitment is defined as `hash(ATTACHMENT_0_COMMITMENT || ... || ATTACHMENT_N_COMMITMENT)`,
/// i.e., the sequential hash over the individual attachment commitments. Returns `EMPTY_WORD` if
/// no attachments are present.
fn compute_commitment(attachments: &[NoteAttachment]) -> Word {
    if attachments.is_empty() {
        Word::empty()
    } else {
        let elements = attachments_to_elements(attachments);
        Hasher::hash_elements(&elements)
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
        vec![Word::from([1, 1, 1, 1u32]); 2],
    )?)]
    #[test]
    fn note_attachment_serde(#[case] attachment: NoteAttachment) -> anyhow::Result<()> {
        assert_eq!(attachment, NoteAttachment::read_from_bytes(&attachment.to_bytes())?);
        Ok(())
    }

    #[test]
    fn note_attachment_array_fails_on_too_many_words() -> anyhow::Result<()> {
        let too_many_words = NoteAttachment::MAX_NUM_WORDS as usize + 1;
        let words = vec![Word::from([1, 1, 1, 1u32]); too_many_words];
        let err = NoteAttachmentArray::new(words).unwrap_err();

        assert_matches!(err, NoteError::NoteAttachmentArrayTooManyWords(len) => {
            len == too_many_words
        });

        Ok(())
    }

    #[test]
    fn note_attachment_array_fails_on_too_few_words() {
        let words = vec![Word::from([1, 1, 1, 1u32]); 1];
        let err = NoteAttachmentArray::new(words).unwrap_err();
        assert_matches!(err, NoteError::NoteAttachmentArrayTooFewWords(1));
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
        let header = NoteAttachmentHeader::new(NoteAttachmentScheme::new(42)?);
        let deserialized = NoteAttachmentHeader::read_from_bytes(&header.to_bytes())?;
        assert_eq!(header, deserialized);
        Ok(())
    }

    #[test]
    fn note_attachment_header_absent() {
        let header = NoteAttachmentHeader::absent();
        assert!(header.is_absent());
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
            NoteAttachment::new_array(
                NoteAttachmentScheme::new(100)?,
                vec![Word::from([1, 1, 1, 1u32]); 2],
            )?,
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
        // Single word attachment: the attachment commitment is hash(word), so the overall
        // attachments commitment is hash(hash(word)).
        let word_commitment = Hasher::hash_elements(word.as_elements());
        assert_eq!(attachments.commitment(), Hasher::hash_elements(word_commitment.as_elements()));

        Ok(())
    }

    #[test]
    fn note_attachments_to_headers() -> anyhow::Result<()> {
        let attachments = NoteAttachments::new(vec![
            NoteAttachment::new_word(NoteAttachmentScheme::new(42)?, Word::from([1, 2, 3, 4u32])),
            NoteAttachment::new_array(
                NoteAttachmentScheme::new(100)?,
                vec![Word::from([1, 1, 1, 1u32]); 2],
            )?,
        ])?;

        let headers = attachments.to_headers();
        assert_eq!(headers[0].scheme(), Some(NoteAttachmentScheme::new(42)?));
        assert_eq!(headers[1].scheme(), Some(NoteAttachmentScheme::new(100)?));
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
    fn note_attachment_num_words() {
        // Word => 1
        let word = NoteAttachmentContent::new_word(Word::from([1, 2, 3, 4u32]));
        assert_eq!(word.num_words(), 1);

        // Array with 2 words
        let array = NoteAttachmentContent::new_array(vec![Word::from([1, 1, 1, 1u32]); 2]).unwrap();
        assert_eq!(array.num_words(), 2);

        // Array with 3 words
        let array = NoteAttachmentContent::new_array(vec![Word::from([1, 1, 1, 1u32]); 3]).unwrap();
        assert_eq!(array.num_words(), 3);
    }
}
