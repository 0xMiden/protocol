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
use crate::note::{NoteAttachmentHeader, NoteAttachments};

// PARTIAL NOTE METADATA
// ================================================================================================

/// The user-facing metadata associated with a note.
///
/// Contains the sender, note type, and tag. For the full protocol-level encoding (including
/// attachment headers and commitment computation), see [`NoteMetadata`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PartialNoteMetadata {
    /// The ID of the account which created the note.
    sender: AccountId,

    /// Defines how the note is to be stored (e.g. public or private).
    note_type: NoteType,

    /// A value which can be used by the recipient(s) to identify notes intended for them.
    tag: NoteTag,
}

impl PartialNoteMetadata {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`PartialNoteMetadata`] instantiated with the specified parameters.
    ///
    /// The tag defaults to [`NoteTag::default()`]. Use [`PartialNoteMetadata::with_tag`] to set a
    /// specific tag if needed.
    pub fn new(sender: AccountId, note_type: NoteType) -> Self {
        Self {
            sender,
            note_type,
            tag: NoteTag::default(),
        }
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

    /// Returns `true` if the note is private, `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.note_type == NoteType::Private
    }

    /// Returns `true` if the note is public, `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.note_type == NoteType::Public
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Mutates the note's tag by setting it to the provided value.
    pub fn set_tag(&mut self, tag: NoteTag) {
        self.tag = tag;
    }

    /// Returns a new [`PartialNoteMetadata`] with the tag set to the provided value.
    ///
    /// This is a builder method that consumes self and returns a new instance for method chaining.
    pub fn with_tag(mut self, tag: NoteTag) -> Self {
        self.tag = tag;
        self
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialNoteMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.note_type().write_into(target);
        self.sender().write_into(target);
        self.tag().write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.note_type().get_size_hint()
            + self.sender().get_size_hint()
            + self.tag().get_size_hint()
    }
}

impl Deserializable for PartialNoteMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note_type = NoteType::read_from(source)?;
        let sender = AccountId::read_from(source)?;
        let tag = NoteTag::read_from(source)?;

        Ok(PartialNoteMetadata::new(sender, note_type).with_tag(tag))
    }
}

// NOTE METADATA
// ================================================================================================

/// Protocol-level note metadata that combines [`PartialNoteMetadata`] with attachment information.
///
/// This type wraps `PartialNoteMetadata` together with attachment headers and an attachment
/// commitment, and knows how to encode them into a [`Word`] and compute commitments.
///
/// The metadata word is encoded as a single [`Word`] (4 felts) with the following layout:
///
/// ```text
/// 0th felt: [sender_id_suffix (56 bits) | reserved (3 bits) | note_type (1 bit) | version (4 bits)]
/// 1st felt: [sender_id_prefix (64 bits)]
/// 2nd felt: [reserved (32 bits) | note_tag (32 bits)]
/// 3rd felt: [attachment_3_scheme (16 bits) | attachment_2_scheme (16 bits) |
///            attachment_1_scheme (16 bits) | attachment_0_scheme (16 bits)]
/// ```
///
/// Felt validity is guaranteed:
/// - 0th felt: The lower 8 bits of the account ID suffix are `0` by construction, so they can be
///   overwritten. The suffix's MSB is zero so the felt stays valid when lower bits are set.
/// - 1st felt: Equivalent to the account ID prefix, so it inherits its validity.
/// - 2nd felt: The tag is a u32 and the reserved bits are _currently_ set to zero, however users
///   shouldn't assume these are zero.
/// - 3rd felt: Max value is `0xFFFEFFFE_FFFEFFFE` (schemes capped at 65534), which is less than
///   `p`.
///
/// The version is hardcoded to 0 and is reserved for forward compatibility.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NoteMetadata {
    partial_metadata: PartialNoteMetadata,
    attachment_headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT],
    attachments_commitment: Word,
}

impl NoteMetadata {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of bits by which the note type is offset in the first felt of the metadata word.
    const NOTE_TYPE_SHIFT: u64 = 4;

    /// Version 1 of the note metadata encoding.
    ///
    /// If we make this public, we may want to instead consider introducing a `NoteMetadataVersion`
    /// struct, similar to `AccountIdVersion`.
    const VERSION_1: u8 = 1;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`NoteMetadata`] derived from the given partial metadata and attachments.
    ///
    /// The attachment headers and commitment are derived from the provided attachments.
    pub fn new(partial_metadata: PartialNoteMetadata, attachments: &NoteAttachments) -> Self {
        Self::from_parts(partial_metadata, attachments.to_headers(), attachments.to_commitment())
    }

    /// Creates a [`NoteMetadata`] from its raw parts.
    ///
    /// Prefer [`Self::new`] whenever possible.
    pub fn from_parts(
        partial_metadata: PartialNoteMetadata,
        attachment_headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT],
        attachments_commitment: Word,
    ) -> Self {
        Self {
            partial_metadata,
            attachment_headers,
            attachments_commitment,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the inner [`PartialNoteMetadata`].
    pub fn partial_metadata(&self) -> &PartialNoteMetadata {
        &self.partial_metadata
    }

    /// Returns the account which created the note.
    pub fn sender(&self) -> AccountId {
        self.partial_metadata.sender()
    }

    /// Returns the note's type.
    pub fn note_type(&self) -> NoteType {
        self.partial_metadata.note_type()
    }

    /// Returns the tag associated with the note.
    pub fn tag(&self) -> NoteTag {
        self.partial_metadata.tag()
    }

    /// Returns the attachment headers.
    pub fn attachment_headers(&self) -> &[NoteAttachmentHeader; NoteAttachments::MAX_COUNT] {
        &self.attachment_headers
    }

    /// Returns the attachments commitment.
    pub fn attachments_commitment(&self) -> Word {
        self.attachments_commitment
    }

    /// Returns `true` if the note is private, `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.partial_metadata.is_private()
    }

    /// Returns `true` if the note is public, `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.partial_metadata.is_public()
    }

    /// Returns the metadata encoded as a [`Word`].
    ///
    /// See [`NoteMetadata`] docs for the layout.
    pub fn to_metadata_word(&self) -> Word {
        let mut word = Word::empty();
        word[0] = merge_sender_suffix_and_note_type(
            self.partial_metadata.sender.suffix(),
            self.partial_metadata.note_type,
        );
        word[1] = self.partial_metadata.sender.prefix().as_felt();
        word[2] = self.partial_metadata.tag.into();
        word[3] = merge_schemes(self.attachment_headers);
        word
    }

    /// Returns the commitment to the note metadata, which is defined as:
    ///
    /// ```text
    /// hash(NOTE_METADATA_WORD || ATTACHMENTS_COMMITMENT)
    /// ```
    pub fn to_commitment(&self) -> Word {
        Hasher::merge(&[self.to_metadata_word(), self.attachments_commitment])
    }

    /// Consumes self and returns the inner [`PartialNoteMetadata`].
    pub fn into_partial_metadata(self) -> PartialNoteMetadata {
        self.partial_metadata
    }
}

impl Serializable for NoteMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.partial_metadata.write_into(target);

        let present_headers_iter =
            self.attachment_headers.iter().filter(|header| !header.is_absent());

        let num_headers_present = u8::try_from(present_headers_iter.clone().count())
            .expect("num attachments is validated to be at most 4");
        num_headers_present.write_into(target);
        target.write_many(present_headers_iter);

        self.attachments_commitment.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.partial_metadata.get_size_hint()
            + core::mem::size_of::<u8>()
            + self
                .attachment_headers
                .iter()
                .filter(|header| !header.is_absent())
                .map(NoteAttachmentHeader::get_size_hint)
                .sum::<usize>()
            + self.attachments_commitment.get_size_hint()
    }
}

impl Deserializable for NoteMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let partial_metadata = PartialNoteMetadata::read_from(source)?;

        let num_headers_present = u8::read_from(source)? as usize;
        if num_headers_present > NoteAttachments::MAX_COUNT {
            return Err(DeserializationError::InvalidValue(format!(
                "number of attachment headers ({num_headers_present}) exceeds maximum ({})",
                NoteAttachments::MAX_COUNT
            )));
        }

        let mut attachment_headers = [NoteAttachmentHeader::absent(); NoteAttachments::MAX_COUNT];
        for header in attachment_headers.iter_mut().take(num_headers_present) {
            *header = NoteAttachmentHeader::read_from(source)?;
        }

        let attachment_commitment = Word::read_from(source)?;

        Ok(Self::from_parts(partial_metadata, attachment_headers, attachment_commitment))
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
    // note_type at bit 4, version at bits 0..=3 (hardcoded to NoteMetadata::VERSION_1)
    merged |= (note_type_byte as u64) << NoteMetadata::NOTE_TYPE_SHIFT;
    merged |= NoteMetadata::VERSION_1 as u64;

    // SAFETY: The most significant bit of the suffix is zero by construction so the u64 will be a
    // valid felt.
    Felt::try_from(merged).expect("encoded value should be a valid felt")
}

/// Merges four attachment schemes into a single [`Felt`].
///
/// The layout is as follows:
///
/// ```text
/// [attachment_3_scheme (16 bits) | attachment_2_scheme (16 bits) |
///  attachment_1_scheme (16 bits) | attachment_0_scheme (16 bits)]
/// ```
///
/// Max value: `0xFFFEFFFE_FFFEFFFE` < p. Schemes are capped at 65534.
fn merge_schemes(headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT]) -> Felt {
    let mut merged: u64 = headers[0].as_u16() as u64;
    merged |= (headers[1].as_u16() as u64) << 16;
    merged |= (headers[2].as_u16() as u64) << 32;
    merged |= (headers[3].as_u16() as u64) << 48;

    Felt::try_from(merged).expect("encoded value should be a valid felt (schemes <= 65534)")
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use alloc::string::ToString;

    use super::*;
    use crate::note::{NoteAttachment, NoteAttachmentScheme};
    use crate::testing::account_id::ACCOUNT_ID_MAX_ONES;

    #[test]
    fn note_metadata_word_encodes_attachment_header() -> anyhow::Result<()> {
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let partial_metadata =
            PartialNoteMetadata::new(sender, NoteType::Public).with_tag(NoteTag::new(0xff));
        let attachment0 = NoteAttachment::with_word(
            NoteAttachmentScheme::new(1)?,
            Word::from([10, 20, 30, 40u32]),
        );
        let attachment1 = NoteAttachment::with_words(
            NoteAttachmentScheme::new(0xfffe)?,
            vec![Word::from([10, 20, 30, 40u32]), Word::from([10, 20, 30, 40u32])],
        )?;
        let attachments = NoteAttachments::new(vec![attachment0, attachment1])?;
        let metadata = NoteMetadata::new(partial_metadata, &attachments);

        let encoded = metadata.to_metadata_word();

        let tag = encoded[2].as_canonical_u64();
        assert_eq!(tag, 0x0000_0000_0000_00ff);

        let schemes = encoded[3].as_canonical_u64();
        // scheme 3 and 4 are 0, 2 is 0xfffe, 1 is 0x1
        assert_eq!(schemes, 0x0000_0000_fffe_0001);

        Ok(())
    }

    #[rstest::rstest]
    #[case::attachment_none([])]
    #[case::attachment_two_words([
      NoteAttachment::with_word(NoteAttachmentScheme::none(), Word::from([3, 4, 5, 6u32])),
      NoteAttachment::with_word(NoteAttachmentScheme::none(), Word::from([3, 4, 5, 6u32])),
    ])]
    #[case::attachment_word_and_two_arrays([
      NoteAttachment::with_word(NoteAttachmentScheme::none(), Word::from([3, 4, 5, 6u32])),
      NoteAttachment::with_words(
        NoteAttachmentScheme::MAX,
        vec![Word::from([5, 5, 5, 5u32]); 2],
      )?,
      NoteAttachment::with_words(
        NoteAttachmentScheme::MAX,
        vec![Word::from([10, 10, 10, 10u32]); NoteAttachment::MAX_NUM_WORDS as usize],
      )?,
    ])]
    #[test]
    fn note_metadata_serde(
        #[case] attachments: impl IntoIterator<Item = NoteAttachment>,
    ) -> anyhow::Result<()> {
        // Use the Account ID with the maximum one bits to test if the merge function always
        // produces valid felts.
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let note_type = NoteType::Public;
        let tag = NoteTag::new(u32::MAX);
        let partial_metadata = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        let attachments = NoteAttachments::new(attachments.into_iter().collect())?;
        let metadata = NoteMetadata::new(partial_metadata, &attachments);

        // Partial Metadata Roundtrip
        let deserialized = PartialNoteMetadata::read_from_bytes(&partial_metadata.to_bytes())?;
        assert_eq!(deserialized, partial_metadata);

        // Metadata Roundtrip
        let roundtripped = NoteMetadata::read_from_bytes(&metadata.to_bytes())?;
        assert_eq!(roundtripped, metadata);

        Ok(())
    }

    #[test]
    fn note_metadata_header_encodes_v1_as_one() {
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let metadata = PartialNoteMetadata::new(sender, NoteType::Private);
        let metadata = NoteMetadata::new(metadata, &NoteAttachments::default());

        let metadata = metadata.to_metadata_word();
        let version = metadata[0].as_canonical_u64() & 0b1111;

        assert_eq!(version, NoteMetadata::VERSION_1 as u64);
        assert_eq!(version, 1);
    }
}
