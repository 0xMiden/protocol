use alloc::string::ToString;

use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::note::Note;
use prost::Message;
use rstest::rstest;

use crate::decoded::note_file::CommittedNoteError;
use crate::decoded::note_file::test_utils::note_files;
use crate::note_file::NoteFile;
use crate::{DecodeMessage, Verify, proto};

#[rstest]
#[case::no_version(&[])]
// Field 2 represents an unknown future version. It must not default to V1.
#[case::unknown_future_version(&[0x12, 0])]
fn note_file_protobuf_requires_a_known_version(#[case] bytes: &[u8]) {
    let wire = proto::note_file::NoteFile::decode(bytes).unwrap();

    let error = wire.decode_fields().unwrap_err();

    assert_eq!(
        error.to_string(),
        "version: field miden_objects::proto::note_file::NoteFile::version is missing"
    );
}

#[rstest]
#[case::no_variant(&[])]
// Field 4 represents an unknown future variant. It must not default to a known one.
#[case::unknown_future_variant(&[0x22, 0])]
fn note_file_v1_protobuf_requires_a_known_variant(#[case] bytes: &[u8]) {
    let wire = proto::note_file::NoteFileV1::decode(bytes).unwrap();

    let error = wire.decode_fields().unwrap_err();

    assert_eq!(
        error.to_string(),
        "variant: field miden_objects::proto::note_file::NoteFileV1::variant is missing"
    );
}

#[test]
fn committed_note_rejects_an_inclusion_proof_for_a_different_note() {
    let other_note_id = Note::mock_noop(Word::from([4, 5, 6, 7u32])).id();
    let Some(file @ NoteFile::Committed { .. }) = note_files().pop() else {
        panic!("the last file is the committed one");
    };
    let NoteFile::Committed { note, .. } = &file else {
        unreachable!()
    };

    let mut wire = proto::note_file::NoteFile::from(&file);
    let Some(proto::note_file::note_file::Version::V1(v1)) = wire.version.as_mut() else {
        panic!("the encoder always sets the V1 version");
    };
    let Some(proto::note_file::note_file_v1::Variant::CommittedNote(committed)) =
        v1.variant.as_mut()
    else {
        panic!("the encoder always sets the committed variant");
    };
    committed.proof.as_mut().unwrap().note_id = Some((&other_note_id).into());

    let error = wire.decode_fields().unwrap().verify().unwrap_err();

    assert_matches!(
        crate::test_utils::error_source::<CommittedNoteError>(&error),
        Some(CommittedNoteError::InclusionProofNoteIdMismatch { note_id, proof_note_id })
            if *note_id == note.id() && *proof_note_id == other_note_id
    );
}
