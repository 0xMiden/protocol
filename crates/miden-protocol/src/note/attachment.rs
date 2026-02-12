use alloc::string::ToString;
use alloc::vec::Vec;

use crate::crypto::SequentialCommit;
use crate::errors::NoteError;
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoteAttachment {
    attachment_scheme: NoteAttachmentScheme,
    content: NoteAttachmentContent,
}

impl NoteAttachment {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachment`] from a user-defined type and the provided content.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The attachment content is [`NoteAttachmentKind::None`] but the scheme is not
    ///   [`NoteAttachmentScheme::none`].
    pub fn new(
        attachment_scheme: NoteAttachmentScheme,
        content: NoteAttachmentContent,
    ) -> Result<Self, NoteError> {
        if content.attachment_kind().is_none() && !attachment_scheme.is_none() {
            return Err(NoteError::AttachmentKindNoneMustHaveAttachmentSchemeNone);
        }

        Ok(Self { attachment_scheme, content })
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
    /// - The maximum number of elements exceeds [`NoteAttachmentArray::MAX_NUM_ELEMENTS`].
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

    /// Returns the attachment kind.
    pub fn attachment_kind(&self) -> NoteAttachmentKind {
        self.content.attachment_kind()
    }

    /// Returns a reference to the attachment content.
    pub fn content(&self) -> &NoteAttachmentContent {
        &self.content
    }
}

impl Serializable for NoteAttachment {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.attachment_scheme().write_into(target);
        self.content().write_into(target);
    }
}

impl Deserializable for NoteAttachment {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let attachment_scheme = NoteAttachmentScheme::read_from(source)?;
        let content = NoteAttachmentContent::read_from(source)?;

        Self::new(attachment_scheme, content)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

/// The content of a [`NoteAttachment`].
///
/// If a note attachment is not required, [`NoteAttachmentContent::None`] should be used.
///
/// When a single [`Word`] has sufficient space, [`NoteAttachmentContent::Word`] should be used, as
/// it does not require any hashing. The word itself is encoded into the
/// [`NoteMetadata`](super::NoteMetadata).
///
/// If the space of a [`Word`] is insufficient, the more flexible
/// [`NoteAttachmentContent::Array`] variant can be used. It contains a set of field elements
/// where only their sequential hash is encoded into the [`NoteMetadata`](super::NoteMetadata).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NoteAttachmentContent {
    /// Signals the absence of a note attachment.
    #[default]
    None,

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
    /// - The maximum number of elements exceeds [`NoteAttachmentArray::MAX_NUM_ELEMENTS`].
    pub fn new_array(elements: Vec<Felt>) -> Result<Self, NoteError> {
        NoteAttachmentArray::new(elements).map(Self::from)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`NoteAttachmentKind`].
    pub fn attachment_kind(&self) -> NoteAttachmentKind {
        match self {
            NoteAttachmentContent::None => NoteAttachmentKind::None,
            NoteAttachmentContent::Word(_) => NoteAttachmentKind::Word,
            NoteAttachmentContent::Array(_) => NoteAttachmentKind::Array,
        }
    }

    /// Returns the [`NoteAttachmentContent`] encoded to a [`Word`].
    ///
    /// See the type-level documentation for more details.
    pub fn to_word(&self) -> Word {
        match self {
            NoteAttachmentContent::None => Word::empty(),
            NoteAttachmentContent::Word(word) => *word,
            NoteAttachmentContent::Array(attachment_commitment) => {
                attachment_commitment.commitment()
            },
        }
    }
}

impl Serializable for NoteAttachmentContent {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.attachment_kind().write_into(target);

        match self {
            NoteAttachmentContent::None => (),
            NoteAttachmentContent::Word(word) => {
                word.write_into(target);
            },
            NoteAttachmentContent::Array(attachment_commitment) => {
                attachment_commitment.num_elements().write_into(target);
                target.write_many(&attachment_commitment.elements);
            },
        }
    }
}

impl Deserializable for NoteAttachmentContent {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let attachment_kind = NoteAttachmentKind::read_from(source)?;

        match attachment_kind {
            NoteAttachmentKind::None => Ok(NoteAttachmentContent::None),
            NoteAttachmentKind::Word => {
                let word = Word::read_from(source)?;
                Ok(NoteAttachmentContent::Word(word))
            },
            NoteAttachmentKind::Array => {
                let num_elements = u16::read_from(source)?;
                let elements = source.read_many(num_elements as usize)?;
                Self::new_array(elements)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
            },
        }
    }
}

// NOTE ATTACHMENT COMMITMENT
// ================================================================================================

/// The type contained in [`NoteAttachmentContent::Array`] that commits to a set of field
/// elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAttachmentArray {
    elements: Vec<Felt>,
    commitment: Word,
}

impl NoteAttachmentArray {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum size of a note attachment that commits to a set of elements.
    ///
    /// Each element holds roughly 8 bytes of data and so this allows for a maximum of
    /// 2048 * 8 = 2^14 = 16384 bytes.
    pub const MAX_NUM_ELEMENTS: u16 = 2048;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentArray`] from the provided elements.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The maximum number of elements exceeds [`NoteAttachmentArray::MAX_NUM_ELEMENTS`].
    pub fn new(elements: Vec<Felt>) -> Result<Self, NoteError> {
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
/// A note attachment scheme is an arbitrary 32-bit unsigned integer.
///
/// Value `0` is reserved to signal that the scheme is none or absent. Whenever the kind of
/// attachment is not standardized or interoperability is unimportant, this none value can be
/// used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteAttachmentScheme(u32);

impl NoteAttachmentScheme {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The reserved value to signal an absent note attachment scheme.
    const NONE: u32 = 0;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NoteAttachmentScheme`] from a `u32`.
    pub const fn new(attachment_scheme: u32) -> Self {
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

    /// Returns the note attachment scheme as a u32.
    pub const fn as_u32(&self) -> u32 {
        self.0
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
        self.as_u32().write_into(target);
    }
}

impl Deserializable for NoteAttachmentScheme {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let attachment_scheme = u32::read_from(source)?;
        Ok(Self::new(attachment_scheme))
    }
}

// NOTE ATTACHMENT KIND
// ================================================================================================

/// The type of [`NoteAttachmentContent`].
///
/// See its docs for more details on each type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum NoteAttachmentKind {
    /// Signals the absence of a note attachment.
    #[default]
    None = Self::NONE,

    /// A note attachment consisting of a single [`Word`].
    Word = Self::WORD,

    /// A note attachment consisting of the commitment to a set of felts.
    Array = Self::ARRAY,
}

impl NoteAttachmentKind {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    const NONE: u8 = 0;
    const WORD: u8 = 1;
    const ARRAY: u8 = 2;

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the attachment kind as a u8.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Returns `true` if the attachment kind is `None`, `false` otherwise.
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns `true` if the attachment kind is `Word`, `false` otherwise.
    pub const fn is_word(&self) -> bool {
        matches!(self, Self::Word)
    }

    /// Returns `true` if the attachment kind is `Array`, `false` otherwise.
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array)
    }
}

impl TryFrom<u8> for NoteAttachmentKind {
    type Error = NoteError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            Self::NONE => Ok(Self::None),
            Self::WORD => Ok(Self::Word),
            Self::ARRAY => Ok(Self::Array),
            _ => Err(NoteError::UnknownNoteAttachmentKind(value)),
        }
    }
}

impl core::fmt::Display for NoteAttachmentKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let output = match self {
            NoteAttachmentKind::None => "None",
            NoteAttachmentKind::Word => "Word",
            NoteAttachmentKind::Array => "Array",
        };

        f.write_str(output)
    }
}

impl Serializable for NoteAttachmentKind {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_u8().write_into(target);
    }
}

impl Deserializable for NoteAttachmentKind {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let attachment_kind = u8::read_from(source)?;
        Self::try_from(attachment_kind)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[rstest::rstest]
    #[case::attachment_none(NoteAttachment::default())]
    #[case::attachment_word(NoteAttachment::new_word(NoteAttachmentScheme::new(1), Word::from([3, 4, 5, 6u32])))]
    #[case::attachment_array(NoteAttachment::new_array(
        NoteAttachmentScheme::new(u32::MAX),
        vec![Felt::new(5), Felt::new(6), Felt::new(7)],
    )?)]
    #[test]
    fn note_attachment_serde(#[case] attachment: NoteAttachment) -> anyhow::Result<()> {
        assert_eq!(attachment, NoteAttachment::read_from_bytes(&attachment.to_bytes())?);
        Ok(())
    }

    #[test]
    fn note_attachment_commitment_fails_on_too_many_elements() -> anyhow::Result<()> {
        let too_many_elements = (NoteAttachmentArray::MAX_NUM_ELEMENTS as usize) + 1;
        let elements = vec![Felt::from(1u32); too_many_elements];
        let err = NoteAttachmentArray::new(elements).unwrap_err();

        assert_matches!(err, NoteError::NoteAttachmentArraySizeExceeded(len) => {
            len == too_many_elements
        });

        Ok(())
    }

    #[test]
    fn note_attachment_kind_fails_on_unknown_variant() -> anyhow::Result<()> {
        let err = NoteAttachmentKind::try_from(3u8).unwrap_err();
        assert_matches!(err, NoteError::UnknownNoteAttachmentKind(3u8));
        Ok(())
    }
}
