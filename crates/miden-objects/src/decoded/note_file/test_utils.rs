use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteDetails, NoteInclusionProof, NoteTag};

use crate::note_file::{NoteFile, NoteSyncHint};

/// Returns one file per [`NoteFile`] variant, in declaration order.
pub(crate) fn note_files() -> Vec<NoteFile> {
    let note = Note::mock_noop(Word::from([0, 1, 2, 3u32]));
    let proof = NoteInclusionProof::new(BlockNumber::from(0), 0, Default::default()).unwrap();

    vec![
        NoteFile::NoteId(note.id()),
        NoteFile::ExpectedNote {
            details: NoteDetails::from(&note),
            sync_hint: NoteSyncHint::new(456.into(), NoteTag::from(123)),
        },
        NoteFile::Committed { note, proof },
    ]
}
