pub use proto::transaction::DecodedInputNoteCommitment as InputNoteCommitment;

use crate::decoded::VerificationError;
use crate::{BuildUnchecked, Verify, proto};

#[cfg(test)]
mod tests;

/// Builds the decoded commitment without checking that its nullifier belongs to its note header.
/// A present header is verified, but the caller must establish nullifier/header consistency and
/// authenticate the note's inclusion separately. An absent header is not evidence of inclusion.
impl BuildUnchecked for InputNoteCommitment {
    type Output = miden_protocol::transaction::InputNoteCommitment;
    type Error = VerificationError;
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        Ok(Self::Output::from_parts_unchecked(
            miden_protocol::note::Nullifier::from_raw(self.nullifier),
            self.header.map(Verify::verify).transpose()?,
        ))
    }
}

pub use proto::transaction::DecodedPrivateOutputNote as PrivateOutputNote;

impl Verify for PrivateOutputNote {
    type Verified = miden_protocol::transaction::PrivateOutputNote;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.header.verify()?, self.attachments.verify()?)?)
    }
}

pub use proto::transaction::DecodedPublicOutputNote as PublicOutputNote;

impl Verify for PublicOutputNote {
    type Verified = miden_protocol::transaction::PublicOutputNote;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(self.note.verify()?)?)
    }
}

pub use proto::transaction::DecodedOutputNote as OutputNote;

impl Verify for OutputNote {
    type Verified = miden_protocol::transaction::OutputNote;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::transaction::output_note::DecodedNote;
        match self.note {
            DecodedNote::Public(note) => Ok(Self::Verified::Public(note.verify()?)),
            DecodedNote::Private(note) => Ok(Self::Verified::Private(note.verify()?)),
        }
    }
}

pub use proto::transaction::DecodedAuthenticatedInputNote as AuthenticatedInputNote;

/// Checks proof/note identity, not inclusion against a trusted block root.
impl Verify for AuthenticatedInputNote {
    type Verified = miden_protocol::transaction::InputNote;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let note = self.note.verify()?;
        let (proof_id, proof) = self.proof.verify()?;
        if proof_id != note.id() {
            return Err(InputNoteError::IdMismatch {
                transmitted: proof_id,
                decoded: note.id(),
            }
            .into());
        }
        Ok(Self::Verified::authenticated(note, proof))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InputNoteError {
    #[error("note ID mismatch: transmitted {transmitted}, decoded {decoded}")]
    IdMismatch {
        transmitted: miden_protocol::note::NoteId,
        decoded: miden_protocol::note::NoteId,
    },
}

pub use proto::transaction::DecodedInputNote as InputNote;

impl Verify for InputNote {
    type Verified = miden_protocol::transaction::InputNote;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use proto::transaction::input_note::DecodedNote;
        match self.note {
            DecodedNote::Authenticated(note) => note.verify(),
            DecodedNote::Unauthenticated(note) => {
                Ok(Self::Verified::unauthenticated(note.verify()?))
            },
        }
    }
}

pub use proto::transaction::DecodedInputNotes as InputNotes;

impl Verify for InputNotes {
    type Verified = miden_protocol::transaction::InputNotes<miden_protocol::transaction::InputNote>;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let notes = self.notes.into_iter().map(Verify::verify).collect::<Result<_, _>>()?;
        Ok(Self::Verified::new(notes)?)
    }
}
