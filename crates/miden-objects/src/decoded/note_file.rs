//! Domain construction for decoded note file messages.

use miden_protobuf::unwrap_infallible;
use miden_protocol::note::NoteId;
pub use proto::note_file::DecodedNoteSyncHint as NoteSyncHint;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
pub(crate) mod test_utils;
#[cfg(test)]
mod tests;

impl Verify for NoteSyncHint {
    type Verified = crate::note_file::NoteSyncHint;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            unwrap_infallible(self.after_block_num.verify()),
            miden_protocol::note::NoteTag::new(self.tag),
        ))
    }
}

pub use proto::note_file::DecodedExpectedNote as ExpectedNote;

impl Verify for ExpectedNote {
    type Verified = crate::note_file::NoteFile;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::ExpectedNote {
            details: self.details.verify()?,
            sync_hint: unwrap_infallible(self.sync_hint.verify()),
        })
    }
}

pub use proto::note_file::DecodedCommittedNote as CommittedNote;

impl Verify for CommittedNote {
    type Verified = crate::note_file::NoteFile;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let note = self.note.verify()?;
        let (proof_note_id, proof) = self.proof.verify()?;
        if proof_note_id != note.id() {
            return Err(CommittedNoteError::InclusionProofNoteIdMismatch {
                note_id: note.id(),
                proof_note_id,
            }
            .into());
        }
        Ok(Self::Verified::Committed { note, proof })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CommittedNoteError {
    #[error("inclusion proof commits to note ID {proof_note_id} but the note's ID is {note_id}")]
    InclusionProofNoteIdMismatch { note_id: NoteId, proof_note_id: NoteId },
}

pub use proto::note_file::DecodedNoteFile as NoteFile;

impl Verify for NoteFile {
    type Verified = crate::note_file::NoteFile;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        match self.version {
            proto::note_file::note_file::DecodedVersion::V1(file) => file.verify(),
        }
    }
}

pub use proto::note_file::DecodedNoteFileV1 as NoteFileV1;

impl Verify for NoteFileV1 {
    type Verified = crate::note_file::NoteFile;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::note_file::note_file_v1::DecodedVariant;

        match self.variant {
            DecodedVariant::NoteId(note_id) => {
                Ok(Self::Verified::NoteId(unwrap_infallible(note_id.verify())))
            },
            DecodedVariant::ExpectedNote(note) => note.verify(),
            DecodedVariant::CommittedNote(note) => note.verify(),
        }
    }
}
