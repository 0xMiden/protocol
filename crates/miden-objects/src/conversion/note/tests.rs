use miden_protocol::Word;
use miden_protocol::note::Note;
use prost::Message;

use crate::{DecodeMessage, Verify, proto};

#[test]
fn note_details_roundtrip() {
    let note = miden_protocol::note::Note::mock_noop(Word::empty());
    let (assets, _, recipient, _) = note.into_parts();
    let details = miden_protocol::note::NoteDetails::new(assets, recipient);
    let wire = proto::note::NoteDetails::from(&details);
    assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), details);
}

#[test]
fn partial_note_metadata_roundtrips_without_attachment_fields() {
    use miden_protocol::note::{NoteType, PartialNoteMetadata};
    let metadata = PartialNoteMetadata::new(
        miden_protocol::account::AccountId::dummy(
            [1; 15],
            miden_protocol::account::AccountIdVersion::Version1,
            miden_protocol::account::AccountType::Private,
            miden_protocol::account::AssetCallbackFlag::Disabled,
        ),
        NoteType::Public,
    );
    let wire: proto::note::PartialNoteMetadata = metadata.into();
    assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), metadata);
}

#[test]
fn note_metadata_roundtrips_through_flat_v1_protobuf_bytes() {
    let metadata = *Note::mock_noop(Word::empty()).metadata();

    let encoded = proto::note::NoteMetadata::from(metadata).encode_to_vec();
    let message = proto::note::NoteMetadata::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.version, proto::note::NoteVersion::V1 as i32);
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), metadata);
}

#[test]
fn note_protobuf_roundtrips_through_versioned_note_metadata() {
    let note = Note::mock_noop(Word::empty());

    let encoded = proto::note::Note::from(note.clone()).encode_to_vec();
    let message = proto::note::Note::decode(encoded.as_slice()).unwrap();

    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), note);
}

#[test]
fn note_protobuf_reconstructs_attachment_metadata_from_structured_attachments() {
    let note = Note::mock_noop(Word::empty());
    let message = proto::note::Note::from(note.clone());
    assert_eq!(message.metadata.as_ref().unwrap().tag, note.metadata().tag().as_u32());
    assert_eq!(message.decode_fields().unwrap().verify().unwrap(), note);
}
