use miden_protocol::note::{Note, NoteId};

use crate::test_utils::dummy_word;

pub(crate) fn note_id(value: u32) -> NoteId {
    Note::mock_noop(dummy_word(value)).id()
}
