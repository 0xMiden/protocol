use alloc::string::ToString;

use miden_core::field::PrimeField64;

use super::execution_hint::NoteExecutionHint;
use super::{
    AccountId,
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Felt,
    NoteError,
    NoteTag,
    NoteType,
    Serializable,
    Word,
};

// NOTE METADATA
// ================================================================================================

/// Metadata associated with a note.
///
/// Note type and tag must be internally consistent according to the following rules:
///
/// - For private and encrypted notes, the two most significant bits of the tag must be `0b11`.
/// - For public notes, the two most significant bits of the tag can be set to any value.
///
/// # Word layout & validity
///
/// [`NoteMetadata`] can be encoded into a [`Word`] with the following layout:
///
/// ```text
/// 1st felt: [sender_id_prefix (64 bits)]
/// 2nd felt: [sender_id_suffix (56 bits) | note_type (2 bits) | note_execution_hint_tag (6 bits)]
/// 3rd felt: [note_execution_hint_payload (32 bits) | note_tag (32 bits)]
/// 4th felt: [aux (64 bits)]
/// ```
///
/// The rationale for the above layout is to ensure the validity of each felt:
/// - 1st felt: Is equivalent to the prefix of the account ID so it inherits its validity.
/// - 2nd felt: The lower 8 bits of the account ID suffix are `0` by construction, so that they can
///   be overwritten with other data. The suffix is designed such that it retains its felt validity
///   even if all of its lower 8 bits are be set to `1`. This is because the most significant bit is
///   always zero.
/// - 3rd felt: The note execution hint payload must contain at least one `0` bit in its encoding,
///   so the upper 32 bits of the felt will contain at least one `0` bit making the entire felt
///   valid.
/// - 4th felt: The `aux` value must be a felt itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoteMetadata {
    /// The ID of the account which created the note.
    sender: AccountId,

    /// Defines how the note is to be stored (e.g. public or private).
    note_type: NoteType,

    /// A value which can be used by the recipient(s) to identify notes intended for them.
    tag: NoteTag,

    /// An arbitrary user-defined value.
    aux: Felt,

    /// Specifies when a note is ready to be consumed.
    execution_hint: NoteExecutionHint,
}

impl NoteMetadata {
    /// Returns a new [NoteMetadata] instantiated with the specified parameters.
    ///
    /// # Errors
    /// Returns an error if the note type and note tag are inconsistent.
    pub fn new(
        sender: AccountId,
        note_type: NoteType,
        tag: NoteTag,
        execution_hint: NoteExecutionHint,
        aux: Felt,
    ) -> Result<Self, NoteError> {
        let tag = tag.validate(note_type)?;
        Ok(Self {
            sender,
            note_type,
            tag,
            aux,
            execution_hint,
        })
    }

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

    /// Returns the execution hint associated with the note.
    pub fn execution_hint(&self) -> NoteExecutionHint {
        self.execution_hint
    }

    /// Returns the note's aux field.
    pub fn aux(&self) -> Felt {
        self.aux
    }

    /// Returns `true` if the note is private.
    pub fn is_private(&self) -> bool {
        self.note_type == NoteType::Private
    }
}

impl From<NoteMetadata> for Word {
    /// Convert a [`NoteMetadata`] into a [`Word`].
    ///
    /// The produced layout of the word is documented on the [`NoteMetadata`] type.
    fn from(metadata: NoteMetadata) -> Self {
        (&metadata).into()
    }
}

impl From<&NoteMetadata> for Word {
    /// Convert a [`NoteMetadata`] into a [`Word`].
    ///
    /// The produced layout of the word is documented on the [`NoteMetadata`] type.
    fn from(metadata: &NoteMetadata) -> Self {
        let mut elements = Word::empty();
        elements[0] = metadata.sender.prefix().as_felt();
        elements[1] = merge_id_type_and_hint_tag(
            metadata.sender.suffix(),
            metadata.note_type,
            metadata.execution_hint,
        );
        elements[2] = merge_note_tag_and_hint_payload(metadata.execution_hint, metadata.tag);
        elements[3] = metadata.aux;
        elements
    }
}

impl TryFrom<Word> for NoteMetadata {
    type Error = NoteError;

    /// Tries to decode a [`Word`] into a [`NoteMetadata`].
    ///
    /// The expected layout of the word is documented on the [`NoteMetadata`] type.
    fn try_from(elements: Word) -> Result<Self, Self::Error> {
        let sender_id_prefix: Felt = elements[0];

        let (sender_id_suffix, note_type, execution_hint_tag) =
            unmerge_id_type_and_hint_tag(elements[1])?;

        let sender = AccountId::try_from([sender_id_prefix, sender_id_suffix])
            .map_err(NoteError::NoteSenderInvalidAccountId)?;

        let (execution_hint, note_tag) =
            unmerge_note_tag_and_hint_payload(elements[2], execution_hint_tag)?;

        Self::new(sender, note_type, note_tag, execution_hint, elements[3])
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for NoteMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        Word::from(self).write_into(target);
    }
}

impl Deserializable for NoteMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let word = Word::read_from(source)?;
        Self::try_from(word).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Merges the suffix of an [`AccountId`], a [`NoteType`] and the tag of a
/// [`NoteExecutionHint`] into a single [`Felt`].
///
/// The layout is as follows:
///
/// ```text
/// [sender_id_suffix (56 bits) | note_type (2 bits) | note_execution_hint_tag (6 bits)]
/// ```
///
/// One of the upper 16 bits is guaranteed to be zero due to the guarantees of the epoch in the
/// account ID.
///
/// Note that `sender_id_suffix` is the suffix of the sender's account ID.
fn merge_id_type_and_hint_tag(
    sender_id_suffix: Felt,
    note_type: NoteType,
    note_execution_hint: NoteExecutionHint,
) -> Felt {
    let mut merged = sender_id_suffix.as_canonical_u64();

    let type_bits = note_type as u8;
    let (tag_bits, _) = note_execution_hint.into_parts();

    debug_assert!(type_bits & 0b1111_1100 == 0, "note type must not contain values >= 4");
    debug_assert!(
        tag_bits & 0b1100_0000 == 0,
        "note execution hint tag must not contain values >= 64"
    );

    // Note: The least significant byte of the second AccountId felt is zero by construction so we
    // can overwrite it.
    merged |= (type_bits << 6) as u64;
    merged |= tag_bits as u64;

    // SAFETY: The most significant bit of the suffix is zero by construction so the bytes will be a
    // valid felt.
    Felt::new(merged)
}

/// Unmerges the given felt into the suffix of an [`AccountId`], a [`NoteType`] and the tag of
/// a [`NoteExecutionHint`].
fn unmerge_id_type_and_hint_tag(element: Felt) -> Result<(Felt, NoteType, u8), NoteError> {
    let element = element.as_canonical_u64();

    // Cut off the least significant byte.
    let least_significant_byte = element as u8;
    let note_type_bits = (least_significant_byte & 0b1100_0000) >> 6;
    let tag_bits = least_significant_byte & 0b0011_1111;

    let note_type = NoteType::try_from(note_type_bits)?;

    // Set least significant byte to zero.
    let element = element & 0xffff_ffff_ffff_ff00;

    // SAFETY: The input was a valid felt and we cleared additional bits and did not set any
    // bits, so it must still be a valid felt.
    let sender_id_suffix = Felt::new(element);

    Ok((sender_id_suffix, note_type, tag_bits))
}

/// Merges the [`NoteExecutionHint`] payload and a [`NoteTag`] into a single [`Felt`].
///
/// The layout is as follows:
///
/// ```text
/// [note_execution_hint_payload (32 bits) | note_tag (32 bits)]
/// ```
///
/// One of the upper 32 bits is guaranteed to be zero.
fn merge_note_tag_and_hint_payload(
    note_execution_hint: NoteExecutionHint,
    note_tag: NoteTag,
) -> Felt {
    let (_, payload) = note_execution_hint.into_parts();
    let note_tag: u32 = note_tag.into();

    debug_assert_ne!(
        payload,
        u32::MAX,
        "payload should never be u32::MAX as it would produce an invalid felt"
    );

    let felt_int = ((payload as u64) << 32) | (note_tag as u64);

    // SAFETY: The payload is guaranteed to never be u32::MAX so at least one of the upper 32 bits
    // is zero, hence the felt is valid even if note_tag is u32::MAX.
    Felt::new(felt_int)
}

/// Unmerges the given felt into a [`NoteExecutionHint`] payload and a [`NoteTag`] and constructs a
/// [`NoteExecutionHint`] from the unmerged payload and the given `note_execution_hint_tag`.
fn unmerge_note_tag_and_hint_payload(
    element: Felt,
    note_execution_hint_tag: u8,
) -> Result<(NoteExecutionHint, NoteTag), NoteError> {
    let element = element.as_canonical_u64();

    let payload = (element >> 32) as u32;
    let note_tag = (element & 0xffff_ffff) as u32;

    let execution_hint = NoteExecutionHint::from_parts(note_execution_hint_tag, payload)?;
    let note_tag = NoteTag::from(note_tag);

    Ok((execution_hint, note_tag))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use anyhow::Context;

    use super::*;
    use crate::testing::account_id::ACCOUNT_ID_MAX_ONES;

    #[test]
    fn note_metadata_serde() -> anyhow::Result<()> {
        // Use the Account ID with the maximum one bits to test if the merge function always
        // produces valid felts.
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let note_type = NoteType::Public;
        let tag = NoteTag::from_account_id(sender);
        let aux = Felt::new(0xffff_ffff_0000_0000u64);

        for execution_hint in [
            NoteExecutionHint::always(),
            NoteExecutionHint::none(),
            NoteExecutionHint::on_block_slot(10, 11, 12),
            NoteExecutionHint::after_block((u32::MAX - 1).into()).unwrap(),
        ] {
            let metadata = NoteMetadata::new(sender, note_type, tag, execution_hint, aux).unwrap();
            NoteMetadata::read_from_bytes(&metadata.to_bytes())
                .context(format!("failed for execution hint {execution_hint:?}"))?;
        }

        Ok(())
    }

    #[test]
    fn merge_and_unmerge_id_type_and_hint() {
        // Use the Account ID with the maximum one bits to test if the merge function always
        // produces valid felts.
        let sender = AccountId::try_from(ACCOUNT_ID_MAX_ONES).unwrap();
        let sender_id_suffix = sender.suffix();

        let note_type = NoteType::Public;
        let note_execution_hint = NoteExecutionHint::OnBlockSlot {
            round_len: 10,
            slot_len: 11,
            slot_offset: 12,
        };

        let merged_value =
            merge_id_type_and_hint_tag(sender_id_suffix, note_type, note_execution_hint);
        let (extracted_suffix, extracted_note_type, extracted_note_execution_hint_tag) =
            unmerge_id_type_and_hint_tag(merged_value).unwrap();

        assert_eq!(note_type, extracted_note_type);
        assert_eq!(note_execution_hint.into_parts().0, extracted_note_execution_hint_tag);
        assert_eq!(sender_id_suffix, extracted_suffix);

        let note_type = NoteType::Private;
        let note_execution_hint = NoteExecutionHint::Always;

        let merged_value =
            merge_id_type_and_hint_tag(sender_id_suffix, note_type, note_execution_hint);
        let (extracted_suffix, extracted_note_type, extracted_note_execution_hint_tag) =
            unmerge_id_type_and_hint_tag(merged_value).unwrap();

        assert_eq!(note_type, extracted_note_type);
        assert_eq!(note_execution_hint.into_parts().0, extracted_note_execution_hint_tag);
        assert_eq!(sender_id_suffix, extracted_suffix);

        let note_type = NoteType::Private;
        let note_execution_hint = NoteExecutionHint::None;

        let merged_value =
            merge_id_type_and_hint_tag(sender_id_suffix, note_type, note_execution_hint);
        let (extracted_suffix, extracted_note_type, extracted_note_execution_hint_tag) =
            unmerge_id_type_and_hint_tag(merged_value).unwrap();

        assert_eq!(note_type, extracted_note_type);
        assert_eq!(note_execution_hint.into_parts().0, extracted_note_execution_hint_tag);
        assert_eq!(sender_id_suffix, extracted_suffix);
    }
}
