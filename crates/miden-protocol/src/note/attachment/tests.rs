use assert_matches::assert_matches;

use super::*;

#[rstest::rstest]
#[case::attachment_word(NoteAttachment::with_word(NoteAttachmentScheme::new(1)?, Word::from([3, 4, 5, 6u32])))]
#[case::attachment_words(NoteAttachment::with_words(
        NoteAttachmentScheme::MAX,
        vec![Word::from([1, 1, 1, 1u32]); 2],
    )?)]
#[test]
fn note_attachment_serde(#[case] attachment: NoteAttachment) -> anyhow::Result<()> {
    assert_eq!(attachment, NoteAttachment::read_from_bytes(&attachment.to_bytes())?);
    Ok(())
}

#[test]
fn note_attachment_content_fails_on_too_many_words() -> anyhow::Result<()> {
    let too_many_words = NoteAttachment::MAX_NUM_WORDS as usize + 1;
    let words = vec![Word::from([1, 1, 1, 1u32]); too_many_words];
    let err = NoteAttachmentContent::new(words).unwrap_err();

    assert_matches!(err, NoteError::NoteAttachmentContentTooManyWords(len) => {
        len == too_many_words
    });

    Ok(())
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
    let attachment = NoteAttachment::with_word(scheme, Word::from([1, 2, 3, 4u32]));
    let attachments = NoteAttachments::new(vec![attachment; NoteAttachments::MAX_COUNT])?;
    assert_eq!(attachments.num_attachments() as usize, NoteAttachments::MAX_COUNT);

    // Exceeding MAX_COUNT should fail.
    let err =
        NoteAttachments::new(vec![
            NoteAttachment::with_word(scheme, Word::from([1, 2, 3, 4u32]));
            NoteAttachments::MAX_COUNT + 1
        ])
        .unwrap_err();
    assert_matches!(err, NoteError::TooManyAttachments(5));

    Ok(())
}

#[test]
fn note_attachments_serde() -> anyhow::Result<()> {
    let attachments = NoteAttachments::new(vec![
        NoteAttachment::with_word(NoteAttachmentScheme::new(1)?, Word::from([1, 2, 3, 4u32])),
        NoteAttachment::with_words(
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
    assert_eq!(attachments.to_commitment(), Word::empty());
}

#[test]
fn note_attachments_commitment_single_word() -> anyhow::Result<()> {
    let word = Word::from([10, 20, 30, 40u32]);
    let attachments =
        NoteAttachments::new(vec![NoteAttachment::with_word(NoteAttachmentScheme::new(1)?, word)])?;
    // Single word attachment: the attachment commitment is hash(word), so the overall
    // attachments commitment is hash(hash(word)).
    let word_commitment = Hasher::hash_elements(word.as_elements());
    assert_eq!(
        attachments.to_commitment(),
        Hasher::hash_elements(word_commitment.as_elements())
    );

    Ok(())
}

#[test]
fn note_attachments_to_headers() -> anyhow::Result<()> {
    let attachments = NoteAttachments::new(vec![
        NoteAttachment::with_word(NoteAttachmentScheme::new(42)?, Word::from([1, 2, 3, 4u32])),
        NoteAttachment::with_words(
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
        NoteAttachment::with_word(NoteAttachmentScheme::new(1)?, Word::from([1, 2, 3, 4u32]));
    let attachments = NoteAttachments::new(vec![word_att.clone()])?;
    let vec = attachments.into_vec();
    assert_eq!(vec, vec![word_att]);

    Ok(())
}

#[test]
fn note_attachment_num_words() {
    // 1 word
    let content = NoteAttachmentContent::new(vec![Word::from([1, 2, 3, 4u32])]).unwrap();
    assert_eq!(content.num_words(), 1);

    // 2 words
    let content = NoteAttachmentContent::new(vec![Word::from([1, 1, 1, 1u32]); 2]).unwrap();
    assert_eq!(content.num_words(), 2);

    // 3 words
    let content = NoteAttachmentContent::new(vec![Word::from([1, 1, 1, 1u32]); 3]).unwrap();
    assert_eq!(content.num_words(), 3);
}
