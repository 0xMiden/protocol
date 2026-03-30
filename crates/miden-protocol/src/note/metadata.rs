use super::{
    AccountId,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Felt,
    NoteTag,
    NoteType,
    Serializable,
    Word,
};
use crate::Hasher;
use crate::errors::NoteError;
use crate::note::{NoteAttachment, NoteAttachmentKind, NoteAttachmentScheme};

// CONSTANTS
// ================================================================================================

/// The number of bits by which the note type is offset in the first felt of the note metadata.
const NOTE_TYPE_SHIFT: u64 = 4;

// NOTE METADATA
// ================================================================================================

/// The metadata associated with a note.
///
/// Note metadata consists of two parts:
/// - The header of the metadata, which consists of:
///   - the sender of the note
///   - the [`NoteType`]
///   - the [`NoteTag`]
///   - type information about the [`NoteAttachment`].
/// - The optional [`NoteAttachment`].
///
/// # Word layout & validity
///
/// [`NoteMetadata`] can be encoded into two words, a header and an attachment word.
///
/// The header word has the following layout:
///
/// ```text
/// 0th felt: [sender_id_suffix (56 bits) | reserved (3 bits) | note_type (1 bit) | version (4 bits)]
/// 1st felt: [sender_id_prefix (64 bits)]
/// 2nd felt: [32 zero bits | note_tag (32 bits)]
/// 3rd felt: [30 zero bits | attachment_kind (2 bits) | attachment_scheme (32 bits)]
/// ```
///
/// The felt validity of each part of the layout is guaranteed:
/// - 1st felt: The lower 8 bits of the account ID suffix are `0` by construction, so that they can
///   be overwritten with other data. The suffix' most significant bit must be zero such that the
///   entire felt retains its validity even if all of its lower 8 bits are set to `1`. So the note
///   type and version can be comfortably encoded.
/// - 2nd felt: Is equivalent to the prefix of the account ID so it inherits its validity.
/// - 3rd felt: The upper 32 bits are always zero.
/// - 4th felt: The upper 30 bits are always zero.
///
/// The version is hardcoded to 0 and is reserved to make it easier to introduce another version.
///
/// The value of the attachment word depends on the
/// [`NoteAttachmentKind`](crate::note::NoteAttachmentKind):
/// - [`NoteAttachmentKind::None`](crate::note::NoteAttachmentKind::None): Empty word.
/// - [`NoteAttachmentKind::Word`](crate::note::NoteAttachmentKind::Word): The raw word itself.
/// - [`NoteAttachmentKind::Array`](crate::note::NoteAttachmentKind::Array): The commitment to the
///   elements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteMetadata {
    /// The ID of the account which created the note.
    sender: AccountId,

    /// Defines how the note is to be stored (e.g. public or private).
    note_type: NoteType,

    /// A value which can be used by the recipient(s) to identify notes intended for them.
    tag: NoteTag,

    /// The optional attachment of a note's metadata.
    ///
    /// Defaults to [`NoteAttachment::default`].
    attachment: NoteAttachment,
}

impl NoteMetadata {
    /// Version 0 of the note metadata encoding.
    ///
    /// If we make this public, we may want to instead consider introducing a `NoteMetadataVersion`
    /// struct, similar to `AccountIdVersion`.
    const VERSION_0: u8 = 0;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`NoteMetadata`] instantiated with the specified parameters.
    ///
    /// The tag defaults to [`NoteTag::default()`]. Use [`NoteMetadata::with_tag`] to set a
    /// specific tag if needed.
    pub fn new(sender: AccountId, note_type: NoteType) -> Self {
        Self {
            sender,
            note_type,
            tag: NoteTag::default(),
            attachment: NoteAttachment::default(),
        }
    }

    /// Reconstructs a [`NoteMetadata`] from a [`NoteMetadataHeader`] and a
    /// [`NoteAttachment`].
    ///
    /// # Errors
    ///
    /// Returns an error if the attachment's kind or scheme do not match those in the header.
    pub fn try_from_header(
        header: NoteMetadataHeader,
        attachment: NoteAttachment,
    ) -> Result<Self, NoteError> {
        if header.attachment_kind != attachment.attachment_kind() {
            return Err(NoteError::AttachmentKindMismatch {
                header_kind: header.attachment_kind,
                attachment_kind: attachment.attachment_kind(),
            });
        }

        if header.attachment_scheme != attachment.attachment_scheme() {
            return Err(NoteError::AttachmentSchemeMismatch {
                header_scheme: header.attachment_scheme,
                attachment_scheme: attachment.attachment_scheme(),
            });
        }

        Ok(Self {
            sender: header.sender,
            note_type: header.note_type,
            tag: header.tag,
            attachment,
        })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the account which created the note.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the note's type.
    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Returns the tag associated with the note.
    pub fn tag(&self) -> NoteTag {
        self.tag
    }

    /// Returns the attachment of the note.
    pub fn attachment(&self) -> &NoteAttachment {
        &self.attachment
    }

    /// Returns `true` if the note is private.
    pub fn is_private(&self) -> bool {
        self.note_type == NoteType::Private
    }

    /// Returns the header of a [`NoteMetadata`] as a [`Word`].
    ///
    /// See [`NoteMetadata`] docs for more details.
    pub fn to_header(&self) -> NoteMetadataHeader {
        NoteMetadataHeader {
            sender: self.sender,
            note_type: self.note_type,
            tag: self.tag,
            attachment_kind: self.attachment().content().attachment_kind(),
            attachment_scheme: self.attachment.attachment_scheme(),
        }
    }

    /// Returns the [`Word`] that represents the header of a [`NoteMetadata`].
    ///
    /// See [`NoteMetadata`] docs for more details.
    pub fn to_header_word(&self) -> Word {
        Word::from(self.to_header())
    }

    /// Returns the [`Word`] that represents the attachment of a [`NoteMetadata`].
    ///
    /// See [`NoteMetadata`] docs for more details.
    pub fn to_attachment_word(&self) -> Word {
        self.attachment.content().to_word()
    }

    /// Returns the commitment to the note metadata, which is defined as:
    ///
    /// ```text
    /// hash(NOTE_METADATA_HEADER || NOTE_METADATA_ATTACHMENT)
    /// ```
    pub fn to_commitment(&self) -> Word {
        Hasher::merge(&[self.to_header_word(), self.to_attachment_word()])
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Mutates the note's tag by setting it to the provided value.
    pub fn set_tag(&mut self, tag: NoteTag) {
        self.tag = tag;
    }

    /// Returns a new [`NoteMetadata`] with the tag set to the provided value.
    ///
    /// This is a builder method that consumes self and returns a new instance for method chaining.
    pub fn with_tag(mut self, tag: NoteTag) -> Self {
        self.tag = tag;
        self
    }

    /// Mutates the note's attachment by setting it to the provided value.
    pub fn set_attachment(&mut self, attachment: NoteAttachment) {
        self.attachment = attachment;
    }

    /// Returns a new [`NoteMetadata`] with the attachment set to the provided value.
    ///
    /// This is a builder method that consumes self and returns a new instance for method chaining.
    pub fn with_attachment(mut self, attachment: NoteAttachment) -> Self {
        self.attachment = attachment;
        self
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.note_type().write_into(target);
        self.sender().write_into(target);
        self.tag().write_into(target);
        self.attachment().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.note_type().get_size_hint()
            + self.sender().get_size_hint()
            + self.tag().get_size_hint()
            + self.attachment().get_size_hint()
    }
}

impl Deserializable for NoteMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note_type = NoteType::read_from(source)?;
        let sender = AccountId::read_from(source)?;
        let tag = NoteTag::read_from(source)?;
        let attachment = NoteAttachment::read_from(source)?;

        Ok(NoteMetadata::new(sender, note_type).with_tag(tag).with_attachment(attachment))
    }
}

// NOTE METADATA HEADER
// ================================================================================================

/// The header representation of [`NoteMetadata`].
///
/// See the metadata's type for details on this type's [`Word`] layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoteMetadataHeader {
    sender: AccountId,
    note_type: NoteType,
    tag: NoteTag,
    attachment_kind: NoteAttachmentKind,
    attachment_scheme: NoteAttachmentScheme,
}

impl NoteMetadataHeader {
    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the account which created the note.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Returns the note's type.
    pub fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Returns the tag associated with the note.
    pub fn tag(&self) -> NoteTag {
        self.tag
    }

    /// Returns the attachment kind.
    pub fn attachment_kind(&self) -> NoteAttachmentKind {
        self.attachment_kind
    }

    /// Returns the attachment scheme.
    pub fn attachment_scheme(&self) -> NoteAttachmentScheme {
        self.attachment_scheme
    }
}

impl From<NoteMetadataHeader> for Word {
    fn from(header: NoteMetadataHeader) -> Self {
        let mut metadata = Word::empty();

        metadata[0] = merge_sender_suffix_and_note_type(header.sender.suffix(), header.note_type);
        metadata[1] = header.sender.prefix().as_felt();
        metadata[2] = Felt::from(header.tag);
        metadata[3] =
            merge_attachment_kind_scheme(header.attachment_kind, header.attachment_scheme);

        metadata
    }
}

impl TryFrom<Word> for NoteMetadataHeader {
    type Error = NoteError;

    /// Decodes a [`NoteMetadataHeader`] from a [`Word`].
    fn try_from(word: Word) -> Result<Self, Self::Error> {
        let (sender_suffix, note_type) = unmerge_sender_suffix_and_note_type(word[0])?;
        let sender_prefix = word[1];
        let tag = u32::try_from(word[2].as_canonical_u64()).map(NoteTag::new).map_err(|_| {
            NoteError::other("failed to convert note tag from metadata header to u32")
        })?;
        let (attachment_kind, attachment_scheme) = unmerge_attachment_kind_scheme(word[3])?;

        let sender =
            AccountId::try_from_elements(sender_suffix, sender_prefix).map_err(|source| {
                NoteError::other_with_source(
                    "failed to decode account ID from metadata header",
                    source,
                )
            })?;

        Ok(Self {
            sender,
            note_type,
            tag,
            attachment_kind,
            attachment_scheme,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Merges the suffix of an [`AccountId`] and note metadata into a single [`Felt`].
///
/// The layout is as follows:
///
/// ```text
/// [sender_id_suffix (56 bits) | reserved (3 bits) | note_type (1 bit) | version (4 bits)]
/// ```
///
/// The most significant bit of the suffix is guaranteed to be zero, so the felt retains its
/// validity.
///
/// The `sender_id_suffix` is the suffix of the sender's account ID.
fn merge_sender_suffix_and_note_type(sender_id_suffix: Felt, note_type: NoteType) -> Felt {
    let mut merged = sender_id_suffix.as_canonical_u64();

    let note_type_byte = note_type as u8;
    debug_assert!(note_type_byte < 2, "note type must not contain values >= 2");
    // note_type at bit 4, version at bits 0..=3 (hardcoded to NoteMetadata::VERSION_0_NUMBER)
    merged |= (note_type_byte as u64) << NOTE_TYPE_SHIFT;
    merged |= NoteMetadata::VERSION_0 as u64;

    // SAFETY: The most significant bit of the suffix is zero by construction so the u64 will be a
    // valid felt.
    Felt::try_from(merged).expect("encoded value should be a valid felt")
}

/// Unmerges the sender ID suffix and note metadata (note type and version).
fn unmerge_sender_suffix_and_note_type(element: Felt) -> Result<(Felt, NoteType), NoteError> {
    // The mask that clears out the lower 8 bits to recover the sender suffix.
    const SENDER_SUFFIX_MASK: u64 = 0xffff_ffff_ffff_ff00;

    let raw = element.as_canonical_u64();
    let version = (raw & 0b1111) as u8;
    let note_type_bit = ((raw >> NOTE_TYPE_SHIFT) & 0b1) as u8;
    let reserved = ((raw >> 5) & 0b111) as u8;

    if reserved != 0 {
        return Err(NoteError::other("reserved bits in note metadata header must be zero"));
    }

    if version != NoteMetadata::VERSION_0 {
        return Err(NoteError::other(format!(
            "unsupported note metadata version {version}, expected {}",
            NoteMetadata::VERSION_0
        )));
    }

    let note_type = NoteType::try_from(note_type_bit).map_err(|source| {
        NoteError::other_with_source("failed to decode note type from metadata header", source)
    })?;

    // No bits were set so felt should still be valid.
    let sender_suffix =
        Felt::try_from(raw & SENDER_SUFFIX_MASK).expect("felt should still be valid");

    Ok((sender_suffix, note_type))
}

/// Merges the [`NoteAttachmentScheme`] and [`NoteAttachmentKind`] into a single [`Felt`].
///
/// The layout is as follows:
///
/// ```text
/// [30 zero bits | attachment_kind (2 bits) | attachment_scheme (32 bits)]
/// ```
fn merge_attachment_kind_scheme(
    attachment_kind: NoteAttachmentKind,
    attachment_scheme: NoteAttachmentScheme,
) -> Felt {
    debug_assert!(attachment_kind.as_u8() < 4, "attachment kind should fit into two bits");
    let mut merged = (attachment_kind.as_u8() as u64) << 32;
    let attachment_scheme = attachment_scheme.as_u32();
    merged |= attachment_scheme as u64;

    Felt::try_from(merged).expect("the upper bit should be zero and the felt therefore valid")
}

/// Unmerges the attachment kind and attachment scheme.
fn unmerge_attachment_kind_scheme(
    element: Felt,
) -> Result<(NoteAttachmentKind, NoteAttachmentScheme), NoteError> {
    let attachment_scheme = element.as_canonical_u64() as u32;
    let attachment_kind = (element.as_canonical_u64() >> 32) as u8;

    let attachment_scheme = NoteAttachmentScheme::new(attachment_scheme);
    let attachment_kind = NoteAttachmentKind::try_from(attachment_kind).map_err(|source| {
        NoteError::other_with_source(
            "failed to decode attachment kind from metadata header",
            source,
        )
    })?;

    Ok((attachment_kind, attachment_scheme))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::*;
    use crate::note::NoteAttachmentScheme;
    use crate::testing::account_id::ACCOUNT_ID_MAX_ONES;

    #[rstest::rstest]
    #[case::attachment_none(NoteAttachment::default())]
    #[case::attachment_raw(NoteAttachment::new_word(NoteAttachmentScheme::new(0), Word::from([3, 4, 5, 6u32])))]
    #[case::attachment_commitment(NoteAttachment::new_array(
        NoteAttachmentScheme::new(u32::MAX),
        vec![Felt::new(5), Felt::new(6), Felt::new(7)],
    )?)]
    #[test]
    fn note_metadata_serde(#[case] attachment: NoteAttachment) -> anyhow::Result<()> {
        // Use the Account ID with the maximum one bits to test if the merge function always
        // produces valid felts.
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let note_type = NoteType::Public;
        let tag = NoteTag::new(u32::MAX);
        let metadata =
            NoteMetadata::new(sender, note_type).with_tag(tag).with_attachment(attachment);

        // Serialization Roundtrip
        let deserialized = NoteMetadata::read_from_bytes(&metadata.to_bytes())?;
        assert_eq!(deserialized, metadata);

        // Metadata Header Roundtrip
        let header = NoteMetadataHeader::try_from(metadata.to_header_word())?;
        assert_eq!(header, metadata.to_header());

        Ok(())
    }
}
