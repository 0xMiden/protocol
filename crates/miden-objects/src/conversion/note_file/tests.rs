use assert_matches::assert_matches;
use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteDetails, NoteTag};
use prost::Message;

use crate::decoded::note_file::test_utils::note_files;
use crate::note_file::{NoteFile, NoteSyncHint};
use crate::{DecodeMessage, Verify, proto};

#[test]
fn note_file_roundtrips_through_protobuf() {
    for file in note_files() {
        let encoded = proto::note_file::NoteFile::from(&file);
        assert_matches!(encoded.version, Some(proto::note_file::note_file::Version::V1(_)));

        let wire = proto::note_file::NoteFile::decode(encoded.encode_to_vec().as_slice()).unwrap();
        assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), file);
    }
}

#[test]
fn note_sync_hint_roundtrips_through_protobuf() {
    let hint = NoteSyncHint::new(456.into(), NoteTag::from(123));

    let wire = proto::note_file::NoteSyncHint::from(hint);
    let wire = proto::note_file::NoteSyncHint::decode(wire.encode_to_vec().as_slice()).unwrap();

    assert_eq!(wire.decode_fields().unwrap().verify().unwrap(), hint);
}

/// A note imported as a file is expected, not yet committed, and is looked up by its tag from the
/// genesis block.
#[test]
fn note_file_from_a_note_expects_it_from_the_genesis_block() {
    let note = Note::mock_noop(Word::from([0, 1, 2, 3u32]));

    let file = NoteFile::from(note.clone());

    assert_eq!(
        file,
        NoteFile::ExpectedNote {
            details: NoteDetails::from(&note),
            sync_hint: NoteSyncHint::new(BlockNumber::from(0), note.metadata().tag()),
        }
    );
}

#[test]
fn note_file_from_a_note_id_carries_only_the_id() {
    let note_id = Note::mock_noop(Word::from([0, 1, 2, 3u32])).id();

    assert_eq!(NoteFile::from(note_id), NoteFile::NoteId(note_id));
}
