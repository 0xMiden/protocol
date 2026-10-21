use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::errors::OutputNoteError;
use miden_protocol::note::Note;

use crate::test_utils::error_source;
use crate::{ConversionError, DecodeMessage, Verify, proto};

#[test]
fn input_note_commitment_builds_unchecked_after_decoding() {
    use crate::BuildUnchecked;
    let header = *miden_protocol::note::Note::mock_noop(Word::empty()).header();
    for header in [None, Some(header)] {
        let wire = proto::transaction::InputNoteCommitment {
            nullifier: Some(Word::empty().into()),
            header: header.map(Into::into),
        };
        let built = wire.decode_fields().unwrap().build_unchecked().unwrap();
        assert_eq!(built.nullifier().as_word(), Word::empty());
        assert_eq!(built.header().copied(), header);
    }
    let mut wire = proto::transaction::InputNoteCommitment {
        nullifier: Some(Word::empty().into()),
        header: Some(header.into()),
    };
    wire.header.as_mut().unwrap().metadata.as_mut().unwrap().note_type = 0;
    assert!(wire.decode_fields().unwrap().build_unchecked().is_err());
}

#[test]
fn private_output_note_defers_cross_field_verification() {
    let note = miden_protocol::note::Note::mock_noop(Word::empty());
    let output = miden_protocol::transaction::PrivateOutputNote::new(
        *note.header(),
        note.attachments().clone(),
    )
    .unwrap();
    let mut wire = proto::transaction::PrivateOutputNote::from(&output);
    assert_eq!(wire.clone().decode_fields().unwrap().verify().unwrap(), output);
    wire.header.as_mut().unwrap().metadata.as_mut().unwrap().note_type =
        proto::note::NoteType::Public as i32;
    assert!(wire.decode_fields().unwrap().verify().is_err());
}

#[test]
fn public_output_note_protobuf_rejects_private_note() {
    let note = Note::mock_noop(Word::empty());
    let error = proto::transaction::PublicOutputNote { note: Some(note.clone().into()) }
        .decode_fields()
        .unwrap()
        .verify()
        .map_err(ConversionError::new)
        .unwrap_err();

    assert_matches!(
        error_source::<OutputNoteError>(&error),
        Some(OutputNoteError::NoteIsPrivate(note_id)) if *note_id == note.id()
    );
}
