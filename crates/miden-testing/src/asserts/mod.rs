//! Assertion macros for note-lifecycle checks in tests.

pub mod notes;

#[doc(hidden)]
pub use notes::{AsNoteId, AsNullifier, MatchesTxInput, OutputNoteSpec, check_output_note_created};
