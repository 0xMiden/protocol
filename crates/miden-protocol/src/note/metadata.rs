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

// NOTE METADATA
// ================================================================================================

/// The metadata associated with a note.
///
/// `NoteMetadata` carries the user-facing fields (sender, note type, tag) together with the
/// attachment headers and the attachments commitment that are part of the note's protocol-level
/// metadata. The actual attachment payloads live on [`Note`](super::Note) as a
/// [`NoteAttachments`] collection; only their headers and commitment are part of the metadata.
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
    /// The ID of the account which created the note.
    sender: AccountId,

    /// Defines how the note is to be stored (e.g. public or private).
    note_type: NoteType,

    /// A value which can be used by the recipient(s) to identify notes intended for them.
    tag: NoteTag,

    /// Per-attachment headers (scheme + size) for up to [`NoteAttachments::MAX_COUNT`] slots.
    attachment_headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT],

    /// Commitment over the note's attachments. Equivalent to [`NoteAttachments::commitment`] of
    /// the originating attachments.
    attachments_commitment: Word,
}

impl NoteMetadata {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of bits by which the note type is offset in the first felt of the metadata word.
    const NOTE_TYPE_SHIFT: u64 = 4;

    /// Version 0 of the note metadata encoding.
    const VERSION_0: u8 = 0;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a [`NoteMetadata`] from its raw parts.
    ///
    /// This is a low-level constructor. To build a complete [`Note`](super::Note) end-to-end,
    /// prefer [`Note::builder`](super::Note::builder), which derives the metadata from
    /// constituent fields without requiring callers to materialize a `NoteMetadata` directly.
    pub fn from_parts(
        sender: AccountId,
        note_type: NoteType,
        tag: NoteTag,
        attachment_headers: [NoteAttachmentHeader; NoteAttachments::MAX_COUNT],
        attachments_commitment: Word,
    ) -> Self {
        Self {
            sender,
            note_type,
            tag,
            attachment_headers,
            attachments_commitment,
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
    /// See [`NoteMetadata`] docs for the layout.
    pub fn to_metadata_word(&self) -> Word {
        let mut word = Word::empty();
        word[0] = merge_sender_suffix_and_note_type(self.sender.suffix(), self.note_type);
        word[1] = self.sender.prefix().as_felt();
        word[2] = self.tag.into();
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

    // CRATE-INTERNAL HELPERS
    // --------------------------------------------------------------------------------------------

    /// Writes only the user-facing core fields (sender, note type, tag), not the attachment
    /// headers or commitment. Used by [`Note`](super::Note) serialization, which carries the full
    /// [`NoteAttachments`] separately and thus does not need to write the derivable fields.
    pub(super) fn write_core<W: ByteWriter>(&self, target: &mut W) {
        self.note_type.write_into(target);
        self.sender.write_into(target);
        self.tag.write_into(target);
    }

    /// Reads the core fields written by [`Self::write_core`].
    pub(super) fn read_core<R: ByteReader>(
        source: &mut R,
    ) -> Result<(AccountId, NoteType, NoteTag), DeserializationError> {
        let note_type = NoteType::read_from(source)?;
        let sender = AccountId::read_from(source)?;
        let tag = NoteTag::read_from(source)?;
        Ok((sender, note_type, tag))
    }
}

// SERIALIZATION
// ================================================================================================

// Standalone `NoteMetadata` serialization writes every field, including the derived
// `attachment_headers` and `attachments_commitment`, so a `NoteMetadata` round-trips on its own
// (e.g., as part of `NoteHeader`). When a `NoteMetadata` is serialized as part of a `Note` or
// `PartialNote` — which already carry the full `NoteAttachments` payload — those types use
// `NoteMetadata::write_core` / `read_core` to skip the derivable fields and avoid wire
// redundancy. Do not consolidate the two paths without preserving that distinction.
impl Serializable for NoteMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_core(target);

        let present_headers_iter =
            self.attachment_headers.iter().filter(|header| !header.is_absent());

        let num_headers_present = u8::try_from(present_headers_iter.clone().count())
            .expect("num attachments is validated to be at most 4");
        num_headers_present.write_into(target);
        target.write_many(present_headers_iter);

        self.attachments_commitment.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.note_type.get_size_hint()
            + self.sender.get_size_hint()
            + self.tag.get_size_hint()
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
        let (sender, note_type, tag) = Self::read_core(source)?;

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

        let attachments_commitment = Word::read_from(source)?;

        Ok(Self::from_parts(
            sender,
            note_type,
            tag,
            attachment_headers,
            attachments_commitment,
        ))
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
    // note_type at bit 4, version at bits 0..=3 (hardcoded to NoteMetadata::VERSION_0)
    merged |= (note_type_byte as u64) << NoteMetadata::NOTE_TYPE_SHIFT;
    merged |= NoteMetadata::VERSION_0 as u64;

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

    use super::*;
    use crate::note::{NoteAttachment, NoteAttachmentScheme};
    use crate::testing::account_id::ACCOUNT_ID_MAX_ONES;

    #[test]
    fn note_metadata_word_encodes_attachment_header() -> anyhow::Result<()> {
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let attachment0 = NoteAttachment::with_word(
            NoteAttachmentScheme::new(1)?,
            Word::from([10, 20, 30, 40u32]),
        );
        let attachment1 = NoteAttachment::with_words(
            NoteAttachmentScheme::new(0xfffe)?,
            vec![Word::from([10, 20, 30, 40u32]), Word::from([10, 20, 30, 40u32])],
        )?;
        let attachments = NoteAttachments::new(vec![attachment0, attachment1])?;
        let metadata = NoteMetadata::from_parts(
            sender,
            NoteType::Public,
            NoteTag::new(0xff),
            attachments.to_headers(),
            attachments.commitment(),
        );

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
        let attachments = NoteAttachments::new(attachments.into_iter().collect())?;
        let metadata = NoteMetadata::from_parts(
            sender,
            note_type,
            tag,
            attachments.to_headers(),
            attachments.commitment(),
        );

        // Roundtrip
        let deserialized = NoteMetadata::read_from_bytes(&metadata.to_bytes())?;
        assert_eq!(deserialized, metadata);

        Ok(())
    }
}
