//! Domain construction for decoded note messages.
use miden_protobuf::unwrap_infallible;
pub use proto::note::DecodedNoteId as NoteId;

use crate::decoded::VerificationError;
use crate::{Verify, proto};

#[cfg(test)]
mod tests;

impl Verify for NoteId {
    type Verified = miden_protocol::note::NoteId;
    type Error = core::convert::Infallible;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::from_raw(self.id))
    }
}

pub use proto::note::DecodedNoteStorage as NoteStorage;

impl Verify for NoteStorage {
    type Verified = miden_protocol::note::NoteStorage;
    type Error = miden_protocol::errors::NoteError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Self::Verified::new(self.items)
    }
}

pub use proto::note::DecodedNoteAttachment as NoteAttachment;

impl Verify for NoteAttachment {
    type Verified = miden_protocol::note::NoteAttachment;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let scheme = miden_protocol::note::NoteAttachmentScheme::new(self.scheme.try_into()?)?;
        Ok(Self::Verified::with_words(scheme, self.words)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NoteMetadataError {
    #[error("note metadata version is unspecified")]
    UnspecifiedVersion,
    #[error("note type is unspecified")]
    UnspecifiedNoteType,
    #[error("too many attachment schemes")]
    TooManyAttachmentSchemes,
}

pub use proto::note::DecodedNoteAttachments as NoteAttachments;

impl Verify for NoteAttachments {
    type Verified = miden_protocol::note::NoteAttachments;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let attachments =
            self.attachments.into_iter().map(Verify::verify).collect::<Result<_, _>>()?;
        Ok(Self::Verified::new(attachments)?)
    }
}

pub use proto::note::DecodedNoteScript as NoteScript;

impl Verify for NoteScript {
    type Verified = miden_protocol::note::NoteScript;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let mast = self.mast.verify()?;
        let entrypoint = miden_protocol::MastNodeId::from_u32_safe(self.entrypoint, &mast)?;
        Ok(Self::Verified::from_parts(alloc::sync::Arc::new(mast), entrypoint)?)
    }
}

pub use proto::note::DecodedNoteRecipient as NoteRecipient;

impl Verify for NoteRecipient {
    type Verified = miden_protocol::note::NoteRecipient;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            self.serial_num,
            self.script.verify()?,
            self.storage.verify()?,
        ))
    }
}

pub use proto::note::DecodedNoteInclusionProof as NoteInclusionProof;

impl Verify for NoteInclusionProof {
    type Verified = (miden_protocol::note::NoteId, miden_protocol::note::NoteInclusionProof);
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok((
            unwrap_infallible(self.note_id.verify()),
            miden_protocol::note::NoteInclusionProof::new(
                unwrap_infallible(self.block_num.verify()),
                self.note_index_in_block.try_into()?,
                self.inclusion_path.verify()?,
            )?,
        ))
    }
}

pub use proto::note::DecodedNoteMetadata as NoteMetadata;

impl Verify for NoteMetadata {
    type Verified = miden_protocol::note::NoteMetadata;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::note::{
            NoteAttachmentHeader,
            NoteAttachmentScheme,
            NoteAttachments,
            NoteTag,
            NoteType,
            PartialNoteMetadata,
        };
        match self.version {
            proto::note::NoteVersion::V1 => {},
            proto::note::NoteVersion::Unspecified => {
                return Err(NoteMetadataError::UnspecifiedVersion.into());
            },
        }
        let note_type = match self.note_type {
            proto::note::NoteType::Private => NoteType::Private,
            proto::note::NoteType::Public => NoteType::Public,
            proto::note::NoteType::Unspecified => {
                return Err(NoteMetadataError::UnspecifiedNoteType.into());
            },
        };
        let partial = PartialNoteMetadata::new(self.sender.verify()?, note_type)
            .with_tag(NoteTag::new(self.tag));
        if self.attachment_schemes.len() > NoteAttachments::MAX_COUNT {
            return Err(NoteMetadataError::TooManyAttachmentSchemes.into());
        }
        let mut headers = [NoteAttachmentHeader::absent(); NoteAttachments::MAX_COUNT];
        for (header, raw) in headers.iter_mut().zip(self.attachment_schemes) {
            let scheme: u16 = raw.try_into()?;
            if scheme != 0 {
                *header = NoteAttachmentHeader::new(NoteAttachmentScheme::new(scheme)?);
            }
        }
        Ok(Self::Verified::from_parts(partial, headers, self.attachments_commitment))
    }
}

pub use proto::note::DecodedNoteDetails as NoteDetails;

impl Verify for NoteDetails {
    type Verified = miden_protocol::note::NoteDetails;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let assets = self.assets.into_iter().map(Verify::verify).collect::<Result<_, _>>()?;
        let assets = miden_protocol::note::NoteAssets::new(assets)?;
        Ok(Self::Verified::new(assets, self.recipient.verify()?))
    }
}

pub use proto::note::DecodedNoteHeader as NoteHeader;

impl Verify for NoteHeader {
    type Verified = miden_protocol::note::NoteHeader;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        Ok(Self::Verified::new(
            miden_protocol::note::NoteDetailsCommitment::from_raw(self.details_commitment),
            self.metadata.verify()?,
        ))
    }
}

pub use proto::note::DecodedPartialNoteMetadata as PartialNoteMetadata;

impl Verify for PartialNoteMetadata {
    type Verified = miden_protocol::note::PartialNoteMetadata;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        use miden_protocol::note::{NoteTag, NoteType};
        if self.version != proto::note::NoteVersion::V1 {
            return Err(NoteMetadataError::UnspecifiedVersion.into());
        }
        let note_type = match self.note_type {
            proto::note::NoteType::Private => NoteType::Private,
            proto::note::NoteType::Public => NoteType::Public,
            proto::note::NoteType::Unspecified => {
                return Err(NoteMetadataError::UnspecifiedNoteType.into());
            },
        };
        Ok(Self::Verified::new(self.sender.verify()?, note_type).with_tag(NoteTag::new(self.tag)))
    }
}

pub use proto::note::DecodedNote as Note;

impl Verify for Note {
    type Verified = miden_protocol::note::Note;
    type Error = VerificationError;
    fn verify(self) -> Result<Self::Verified, Self::Error> {
        let (assets, recipient) = self.note_details.verify()?.into_parts();
        Ok(Self::Verified::with_attachments(
            assets,
            self.metadata.verify()?,
            recipient,
            self.note_attachments.verify()?,
        ))
    }
}
