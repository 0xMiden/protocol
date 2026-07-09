use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteId};

use crate::note::StandardNoteAttachment;

// FEE SPONSORSHIP
// ================================================================================================

/// A [`NoteAttachment`] binding a fee sponsorship note to the feature note it pays for.
///
/// It carries a single word: the [`NoteId`] of the bound feature note.
///
/// The binding must be on an attachment rather than in note storage because the kernel exposes no
/// indexed accessor for an input note's storage items -- only its storage commitment. Attachments,
/// by contrast, *are* readable by index (`input_note::write_attachment_to_memory`), which is what
/// lets a network account's auth procedure inspect the sponsorship carried by every input note.
///
/// The bound value is a [`NoteId`] rather than, say, a recipient, because a note ID commits to the
/// note's assets, metadata and attachments in addition to its recipient. Binding to anything weaker
/// would let an attacker mint a note matching the binding but carrying different assets, and divert
/// the sponsorship to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSponsorship {
    feature_note_id: NoteId,
}

impl FeeSponsorship {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The standardized scheme of [`FeeSponsorship`] attachments.
    pub const ATTACHMENT_SCHEME: NoteAttachmentScheme =
        StandardNoteAttachment::FeeSponsorship.attachment_scheme();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`FeeSponsorship`] bound to the feature note with the provided ID.
    pub fn new(feature_note_id: NoteId) -> Self {
        Self { feature_note_id }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`NoteId`] of the feature note this sponsorship is bound to.
    pub fn feature_note_id(&self) -> NoteId {
        self.feature_note_id
    }
}

// CONVERSIONS
// ================================================================================================

impl From<FeeSponsorship> for NoteAttachment {
    fn from(sponsorship: FeeSponsorship) -> Self {
        NoteAttachment::with_word(
            FeeSponsorship::ATTACHMENT_SCHEME,
            sponsorship.feature_note_id.as_word(),
        )
    }
}

impl TryFrom<&NoteAttachments> for FeeSponsorship {
    type Error = FeeSponsorshipError;

    fn try_from(attachments: &NoteAttachments) -> Result<Self, Self::Error> {
        // Find the first matching attachment. In case of multiple fee sponsorship attachments, we
        // pick the first one as the canonical one, matching `NetworkAccountTarget`.
        let attachment = attachments
            .find(FeeSponsorship::ATTACHMENT_SCHEME)
            .ok_or(FeeSponsorshipError::MissingAttachmentScheme)?;

        Self::try_from(attachment)
    }
}

impl TryFrom<&NoteAttachment> for FeeSponsorship {
    type Error = FeeSponsorshipError;

    fn try_from(attachment: &NoteAttachment) -> Result<Self, Self::Error> {
        if attachment.attachment_scheme() != Self::ATTACHMENT_SCHEME {
            return Err(FeeSponsorshipError::AttachmentSchemeMismatch(
                attachment.attachment_scheme(),
            ));
        }

        let words = attachment.content().as_words();
        if words.len() != 1 {
            return Err(FeeSponsorshipError::AttachmentContentNumWordsMismatch(
                attachment.content().num_words(),
            ));
        }

        Ok(Self::new(NoteId::from_raw(words[0])))
    }
}

// ERRORS
// ================================================================================================

/// Errors that can occur when decoding a [`FeeSponsorship`] attachment.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FeeSponsorshipError {
    /// The note carries no attachment with the fee sponsorship scheme.
    #[error("note does not contain a fee sponsorship attachment")]
    MissingAttachmentScheme,
    /// The attachment's scheme is not the fee sponsorship scheme.
    #[error(
        "attachment scheme {0} did not match expected type {expected}",
        expected = FeeSponsorship::ATTACHMENT_SCHEME
    )]
    AttachmentSchemeMismatch(NoteAttachmentScheme),
    /// The attachment does not consist of exactly one word.
    #[error("fee sponsorship expects attachment content with one word, got {0}")]
    AttachmentContentNumWordsMismatch(u16),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::Word;
    use miden_protocol::note::NoteAttachments;

    use super::*;

    fn note_id() -> NoteId {
        NoteId::from_raw(Word::from([1, 2, 3, 4u32]))
    }

    /// A fee sponsorship attachment round-trips through `NoteAttachment` and `NoteAttachments`.
    #[test]
    fn attachment_round_trips() {
        let sponsorship = FeeSponsorship::new(note_id());
        let attachment = NoteAttachment::from(sponsorship);

        assert_eq!(attachment.attachment_scheme(), FeeSponsorship::ATTACHMENT_SCHEME);
        assert_eq!(FeeSponsorship::try_from(&attachment).unwrap(), sponsorship);

        let attachments = NoteAttachments::from(attachment);
        let decoded = FeeSponsorship::try_from(&attachments).unwrap();
        assert_eq!(decoded.feature_note_id(), note_id());
    }

    /// Decoding an attachment carrying a different scheme fails rather than silently succeeding.
    #[test]
    fn decoding_rejects_scheme_mismatch() {
        let foreign = NoteAttachment::with_word(
            NoteAttachmentScheme::new(99).unwrap(),
            Word::from([1, 2, 3, 4u32]),
        );

        let err = FeeSponsorship::try_from(&foreign).unwrap_err();
        assert_matches!(err, FeeSponsorshipError::AttachmentSchemeMismatch(_));
    }

    /// A note without a fee sponsorship attachment reports it as missing.
    #[test]
    fn decoding_reports_missing_attachment() {
        let attachments = NoteAttachments::default();

        let err = FeeSponsorship::try_from(&attachments).unwrap_err();
        assert_matches!(err, FeeSponsorshipError::MissingAttachmentScheme);
    }
}
