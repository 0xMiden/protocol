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
use crate::note::{NoteAttachmentHeader, NoteAttachmentScheme, NoteAttachments};

// NOTE METADATA
// ================================================================================================

/// The user-facing metadata associated with a note.
///
/// Contains the sender, note type, and tag. For the full protocol-level encoding (including
/// attachment headers and commitment computation), see [`NoteMetadataHeader`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NoteMetadata {
    /// The ID of the account which created the note.
    sender: AccountId,

    /// Defines how the note is to be stored (e.g. public or private).
    note_type: NoteType,

    /// A value which can be used by the recipient(s) to identify notes intended for them.
    tag: NoteTag,
}

impl NoteMetadata {
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

    /// Returns `true` if the note is private.
    pub fn is_private(&self) -> bool {
        self.note_type == NoteType::Private
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
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteMetadata {
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

impl Deserializable for NoteMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let note_type = NoteType::read_from(source)?;
        let sender = AccountId::read_from(source)?;
        let tag = NoteTag::read_from(source)?;

        Ok(NoteMetadata::new(sender, note_type).with_tag(tag))
    }
}

// NOTE METADATA HEADER
// ================================================================================================

/// Protocol-level note metadata header that combines [`NoteMetadata`] with attachment information.
///
/// This type wraps `NoteMetadata` together with attachment headers and an attachment commitment,
/// and knows how to encode them into a [`Word`] and compute commitments.
///
/// The metadata word is encoded as a single [`Word`] (4 felts) with the following layout:
///
/// ```text
/// 0th felt: [sender_id_suffix (56 bits) | reserved (3 bits) | note_type (1 bit) | version (4 bits)]
/// 1st felt: [sender_id_prefix (64 bits)]
/// 2nd felt: [attachment_3_num_words (8 bits) | attachment_2_num_words (8 bits) |
///            attachment_1_num_words (8 bits) | attachment_0_num_words (8 bits) |
///            note_tag (32 bits)]
/// 3rd felt: [attachment_3_scheme (16 bits) | attachment_2_scheme (16 bits) |
///            attachment_1_scheme (16 bits) | attachment_0_scheme (16 bits)]
/// ```
///
/// Felt validity is guaranteed:
/// - 0th felt: The lower 8 bits of the account ID suffix are `0` by construction, so they can be
///   overwritten. The suffix's MSB is zero so the felt stays valid when lower bits are set.
/// - 1st felt: Equivalent to the account ID prefix, so it inherits its validity.
/// - 2nd felt: Max value is `0xFEFEFEFE_FFFFFFFF` (num_words capped at 254, tag at u32::MAX), which
///   is less than the Goldilocks prime `p = 2^64 - 2^32 + 1`.
/// - 3rd felt: Max value is `0xFFFEFFFE_FFFEFFFE` (schemes capped at 65534), which is less than
///   `p`.
///
/// The version is hardcoded to 0 and is reserved for forward compatibility.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NoteMetadataHeader {
    metadata: NoteMetadata,
    attachment_headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT],
    attachments_commitment: Word,
}

impl NoteMetadataHeader {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of bits by which the note type is offset in the first felt of the metadata word.
    const NOTE_TYPE_SHIFT: u64 = 4;

    /// Version 0 of the note metadata encoding.
    const VERSION_0: u8 = 0;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`NoteMetadataHeader`] derived from the given metadata and attachments.
    ///
    /// The attachment headers and commitment are derived from the provided attachments.
    pub fn new(metadata: NoteMetadata, attachments: &NoteAttachments) -> Self {
        Self::from_parts(metadata, attachments.to_headers(), attachments.commitment())
    }

    /// Creates a [`NoteMetadataHeader`] from its raw parts.
    ///
    /// Prefer [`Self::new`] whenever possible.
    pub fn from_parts(
        metadata: NoteMetadata,
        attachment_headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT],
        attachments_commitment: Word,
    ) -> Self {
        Self {
            metadata,
            attachment_headers,
            attachments_commitment,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the inner [`NoteMetadata`].
    pub fn metadata(&self) -> &NoteMetadata {
        &self.metadata
    }

    /// Returns the attachment headers.
    pub fn attachment_headers(&self) -> &[NoteAttachmentHeader; NoteAttachments::MAX_COUNT] {
        &self.attachment_headers
    }

    /// Returns the attachments commitment.
    pub fn attachments_commitment(&self) -> Word {
        self.attachments_commitment
    }

    /// Returns the metadata encoded as a [`Word`].
    ///
    /// See [`NoteMetadataHeader`] docs for the layout.
    pub fn to_metadata_word(&self) -> Word {
        let (num_words, schemes) = extract_num_words_and_schemes(&self.attachment_headers);

        let mut word = Word::empty();
        word[0] = merge_sender_suffix_and_note_type(
            self.metadata.sender.suffix(),
            self.metadata.note_type,
        );
        word[1] = self.metadata.sender.prefix().as_felt();
        word[2] = merge_tag_and_num_words(self.metadata.tag, num_words);
        word[3] = merge_schemes(schemes);
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

    /// Consumes self and returns the inner [`NoteMetadata`].
    pub fn into_metadata(self) -> NoteMetadata {
        self.metadata
    }
}

impl Serializable for NoteMetadataHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.metadata.write_into(target);

        let present_headers_iter =
            self.attachment_headers.iter().filter(|header| !header.is_absent());

        let num_headers_present = u8::try_from(present_headers_iter.clone().count())
            .expect("num attachments is validated to be at most 4");
        num_headers_present.write_into(target);
        target.write_many(present_headers_iter);

        self.attachments_commitment.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.metadata.get_size_hint()
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

impl Deserializable for NoteMetadataHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let metadata = NoteMetadata::read_from(source)?;

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

        Ok(Self::from_parts(metadata, attachment_headers, attachment_commitment))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Extracts the num_words and schemes arrays from the attachment headers.
fn extract_num_words_and_schemes(
    headers: &[NoteAttachmentHeader; NoteAttachments::MAX_COUNT],
) -> (
    [u8; NoteAttachments::MAX_COUNT],
    [NoteAttachmentScheme; NoteAttachments::MAX_COUNT],
) {
    let mut num_words = [0u8; NoteAttachments::MAX_COUNT];
    let mut schemes = [NoteAttachmentScheme::none(); NoteAttachments::MAX_COUNT];
    for (i, header) in headers.iter().enumerate() {
        num_words[i] = header.num_words();
        schemes[i] = header.scheme();
    }
    (num_words, schemes)
}

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
    // note_type at bit 4, version at bits 0..=3 (hardcoded to NoteMetadataHeader::VERSION_0)
    merged |= (note_type_byte as u64) << NoteMetadataHeader::NOTE_TYPE_SHIFT;
    merged |= NoteMetadataHeader::VERSION_0 as u64;

    // SAFETY: The most significant bit of the suffix is zero by construction so the u64 will be a
    // valid felt.
    Felt::try_from(merged).expect("encoded value should be a valid felt")
}

/// Merges the note tag and four attachment num_words into a single [`Felt`].
///
/// The layout is as follows:
///
/// ```text
/// [attachment_3_num_words (8 bits) | attachment_2_num_words (8 bits) |
///  attachment_1_num_words (8 bits) | attachment_0_num_words (8 bits) |
///  note_tag (32 bits)]
/// ```
fn merge_tag_and_num_words(tag: NoteTag, num_words: [u8; 4]) -> Felt {
    let mut merged: u64 = u32::from(tag) as u64;
    merged |= (num_words[0] as u64) << 32;
    merged |= (num_words[1] as u64) << 40;
    merged |= (num_words[2] as u64) << 48;
    merged |= (num_words[3] as u64) << 56;

    Felt::try_from(merged).expect("encoded value should be a valid felt (num_words <= 254)")
}

/// Merges four attachment schemes into a single [`Felt`].
///
/// The layout is as follows:
///
/// ```text
/// [attachment_3_scheme (16 bits) | attachment_2_scheme (16 bits) | attachment_1_scheme (16 bits) | attachment_0_scheme (16 bits)]
/// ```
///
/// Max value: `0xFFFEFFFE_FFFEFFFE` < p. Schemes are capped at 65534.
fn merge_schemes(schemes: [NoteAttachmentScheme; 4]) -> Felt {
    let mut merged: u64 = schemes[0].as_u16() as u64;
    merged |= (schemes[1].as_u16() as u64) << 16;
    merged |= (schemes[2].as_u16() as u64) << 32;
    merged |= (schemes[3].as_u16() as u64) << 48;

    Felt::try_from(merged).expect("encoded value should be a valid felt (schemes <= 65534)")
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::*;
    use crate::note::{NoteAttachment, NoteAttachmentArray, NoteAttachmentScheme};
    use crate::testing::account_id::ACCOUNT_ID_MAX_ONES;

    #[test]
    fn note_metadata_word_encodes_attachment_header() -> anyhow::Result<()> {
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let metadata = NoteMetadata::new(sender, NoteType::Public).with_tag(NoteTag::new(0xff));
        let attachment0 = NoteAttachment::new_word(
            NoteAttachmentScheme::new(1)?,
            Word::from([10, 20, 30, 40u32]),
        );
        let attachment1 = NoteAttachment::new_array(
            NoteAttachmentScheme::new(0xfffe)?,
            vec![Word::from([10, 20, 30, 40u32]), Word::from([10, 20, 30, 40u32])],
        )?;
        let attachments = NoteAttachments::new(vec![attachment0, attachment1])?;
        let metadata_header = NoteMetadataHeader::new(metadata, &attachments);

        let encoded = metadata_header.to_metadata_word();

        let num_words_and_tag = encoded[2].as_canonical_u64();
        // num_words 3 and 4 are 0, 2 encodes to 0x2 and 1 encodes to 0x1
        // tag should encode to 0xff
        assert_eq!(num_words_and_tag, 0x0000_0201_0000_00ff);

        let schemes = encoded[3].as_canonical_u64();
        // scheme 3 and 4 are 0, 2 is 0xfffe, 1 is 0x1
        assert_eq!(schemes, 0x0000_0000_fffe_0001);

        Ok(())
    }

    #[rstest::rstest]
    #[case::attachment_none([])]
    #[case::attachment_two_words([
      NoteAttachment::new_word(NoteAttachmentScheme::none(), Word::from([3, 4, 5, 6u32])),
      NoteAttachment::new_word(NoteAttachmentScheme::none(), Word::from([3, 4, 5, 6u32])),
    ])]
    #[case::attachment_word_and_two_arrays([
      NoteAttachment::new_word(NoteAttachmentScheme::none(), Word::from([3, 4, 5, 6u32])),
      NoteAttachment::new_array(
        NoteAttachmentScheme::MAX,
        vec![Word::from([5, 5, 5, 5u32]); NoteAttachmentArray::MIN_NUM_WORDS as usize],
      )?,
      NoteAttachment::new_array(
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
        let metadata = NoteMetadata::new(sender, note_type).with_tag(tag);
        let attachments = NoteAttachments::new(attachments.into_iter().collect())?;
        let metadata_header = NoteMetadataHeader::new(metadata.clone(), &attachments);

        // Metadata Roundtrip
        let deserialized = NoteMetadata::read_from_bytes(&metadata.to_bytes())?;
        assert_eq!(deserialized, metadata);

        // Metadata Header Roundtrip
        let header = NoteMetadataHeader::read_from_bytes(&metadata_header.to_bytes())?;
        assert_eq!(header, metadata_header);

        Ok(())
    }
}
