use crate::note_file::{NoteFile, NoteSyncHint};
use crate::proto;

#[cfg(test)]
mod tests;

// NOTE SYNC HINT
// ================================================================================================

impl From<&NoteSyncHint> for proto::note_file::NoteSyncHint {
    fn from(hint: &NoteSyncHint) -> Self {
        Self {
            after_block_num: Some(hint.after_block_num().into()),
            tag: hint.tag().as_u32(),
        }
    }
}

impl From<NoteSyncHint> for proto::note_file::NoteSyncHint {
    fn from(hint: NoteSyncHint) -> Self {
        Self::from(&hint)
    }
}

// NOTE FILE
// ================================================================================================

impl From<&NoteFile> for proto::note_file::NoteFile {
    fn from(file: &NoteFile) -> Self {
        let version = proto::note_file::note_file::Version::V1(file.into());
        Self { version: Some(version) }
    }
}

impl From<NoteFile> for proto::note_file::NoteFile {
    fn from(file: NoteFile) -> Self {
        Self::from(&file)
    }
}

impl From<&NoteFile> for proto::note_file::NoteFileV1 {
    fn from(file: &NoteFile) -> Self {
        use proto::note_file::note_file_v1::Variant;

        let variant = match file {
            NoteFile::NoteId(note_id) => Variant::NoteId(note_id.into()),
            NoteFile::ExpectedNote { details, sync_hint } => {
                Variant::ExpectedNote(proto::note_file::ExpectedNote {
                    details: Some(details.into()),
                    sync_hint: Some(sync_hint.into()),
                })
            },
            NoteFile::Committed { note, proof } => {
                Variant::CommittedNote(proto::note_file::CommittedNote {
                    note: Some(note.into()),
                    proof: Some((&note.id(), proof).into()),
                })
            },
        };
        Self { variant: Some(variant) }
    }
}
