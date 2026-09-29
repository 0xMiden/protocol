use alloc::vec::Vec;

use miden_protocol::account::AccountCodeUpgrade;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme, NoteAttachments};
use miden_protocol::utils::serde::DeserializationError;
use miden_protocol::{Felt, Word};

use crate::note::StandardNoteAttachment;

// ACCOUNT CODE UPGRADE ATTACHMENT
// ================================================================================================

/// Carries an [`AccountCodeUpgrade`] in the attachments of a note, so that a transaction consuming
/// the note can upgrade an account to its code.
///
/// The encoding of [`AccountCodeUpgrade::to_elements`], which is also the value of the upgrade's
/// advice map entry, is split into chunks of at most [`NoteAttachment::MAX_NUM_WORDS`] words, one
/// [`NoteAttachment`] per chunk. Code that is too large for a single attachment can thus still be
/// carried by a note, within the limits of [`NoteAttachments`]. The chunks are joined in the order
/// in which they appear in the note's attachments, which the note commits to.
///
/// When the kernel initializes an upgrade that the advice map does not provide the code for, the
/// transaction host looks for an input note whose chunks decode to code that matches the new code
/// commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCodeUpgradeAttachment {
    code_upgrade: AccountCodeUpgrade,
}

impl AccountCodeUpgradeAttachment {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The standardized scheme of [`AccountCodeUpgradeAttachment`] chunks.
    pub const ATTACHMENT_SCHEME: NoteAttachmentScheme =
        StandardNoteAttachment::AccountCodeUpgrade.attachment_scheme();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountCodeUpgradeAttachment`] that carries `code_upgrade`.
    pub fn new(code_upgrade: AccountCodeUpgrade) -> Self {
        Self { code_upgrade }
    }

    /// Decodes the [`AccountCodeUpgradeAttachment`] from the chunks among `attachments`.
    ///
    /// Attachments of other schemes are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `attachments` do not contain any chunk.
    /// - the joined chunks do not encode valid account code.
    pub fn try_from_attachments(
        attachments: &NoteAttachments,
    ) -> Result<Self, AccountCodeUpgradeAttachmentError> {
        let elements: Vec<Felt> = attachments
            .iter()
            .filter(|attachment| attachment.attachment_scheme() == Self::ATTACHMENT_SCHEME)
            .flat_map(|attachment| attachment.as_elements().iter().copied())
            .collect();

        if elements.is_empty() {
            return Err(AccountCodeUpgradeAttachmentError::MissingCodeAttachment);
        }

        AccountCodeUpgrade::try_from_elements(&elements)
            .map(Self::new)
            .map_err(AccountCodeUpgradeAttachmentError::DecodeCode)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the carried code upgrade.
    pub fn code_upgrade(&self) -> &AccountCodeUpgrade {
        &self.code_upgrade
    }

    /// Consumes self and returns the carried code upgrade.
    pub fn into_code_upgrade(self) -> AccountCodeUpgrade {
        self.code_upgrade
    }

    /// Returns the chunks of the carried code upgrade as note attachments.
    ///
    /// # Errors
    ///
    /// Returns an error if a chunk cannot be converted into a note attachment.
    pub fn to_attachments(&self) -> Result<Vec<NoteAttachment>, NoteError> {
        // The encoding is padded to whole words, so there is no remainder.
        let elements = self.code_upgrade.to_elements();
        let words: Vec<Word> = elements
            .as_chunks::<{ Word::NUM_ELEMENTS }>()
            .0
            .iter()
            .map(|word_elements| Word::new(*word_elements))
            .collect();

        words
            .chunks(usize::from(NoteAttachment::MAX_NUM_WORDS))
            .map(|chunk| NoteAttachment::with_words(Self::ATTACHMENT_SCHEME, chunk.to_vec()))
            .collect()
    }
}

// ACCOUNT CODE UPGRADE ATTACHMENT ERROR
// ================================================================================================

/// Errors that can occur when decoding an [`AccountCodeUpgradeAttachment`] from note attachments.
#[derive(Debug, thiserror::Error)]
pub enum AccountCodeUpgradeAttachmentError {
    #[error(
        "note attachments do not contain an attachment of scheme {scheme}",
        scheme = AccountCodeUpgradeAttachment::ATTACHMENT_SCHEME
    )]
    MissingCodeAttachment,
    #[error("failed to decode the account code of the attachments")]
    DecodeCode(#[source] DeserializationError),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_protocol::Word;
    use miden_protocol::account::{AccountCode, AccountCodeUpgrade};
    use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme, NoteAttachments};

    use super::{AccountCodeUpgradeAttachment, AccountCodeUpgradeAttachmentError};
    use crate::testing::account_component::{IncrNonceAuthComponent, MockProceduresComponent};

    /// Returns an attachment carrying code with `num_procedures` procedures.
    fn code_attachment(num_procedures: usize) -> anyhow::Result<AccountCodeUpgradeAttachment> {
        let code = AccountCode::from_components(&[
            IncrNonceAuthComponent.into(),
            MockProceduresComponent::new(num_procedures).into(),
        ])?;

        Ok(AccountCodeUpgradeAttachment::new(AccountCodeUpgrade::new(code)))
    }

    /// The chunks carry the upgrade's advice map entry and decode back to the same upgrade.
    #[rstest::rstest]
    #[case::single_chunk(1, 1)]
    #[case::two_chunks(200, 2)]
    fn attachments_roundtrip(
        #[case] num_procedures: usize,
        #[case] expected_num_chunks: usize,
    ) -> anyhow::Result<()> {
        let attachment = code_attachment(num_procedures)?;

        let chunks = attachment.to_attachments()?;
        assert_eq!(chunks.len(), expected_num_chunks);

        let (_, advice_map_value) = attachment.code_upgrade().to_advice_map_entry();
        let chunk_elements: Vec<_> =
            chunks.iter().flat_map(|chunk| chunk.as_elements().iter().copied()).collect();
        assert_eq!(chunk_elements, advice_map_value);

        let note_attachments = NoteAttachments::new(chunks)?;
        assert_eq!(
            AccountCodeUpgradeAttachment::try_from_attachments(&note_attachments)?,
            attachment
        );

        Ok(())
    }

    #[test]
    fn attachments_without_chunk_are_rejected() -> anyhow::Result<()> {
        let other_attachment =
            NoteAttachment::with_word(NoteAttachmentScheme::new(64)?, Word::empty());
        let note_attachments = NoteAttachments::new(vec![other_attachment])?;

        assert_matches!(
            AccountCodeUpgradeAttachment::try_from_attachments(&note_attachments),
            Err(AccountCodeUpgradeAttachmentError::MissingCodeAttachment)
        );

        Ok(())
    }
}
