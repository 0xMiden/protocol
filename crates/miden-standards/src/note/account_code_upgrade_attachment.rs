use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountCodeUpgrade;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme};
use miden_protocol::utils::serde::DeserializationError;

use crate::note::StandardNoteAttachment;

// ACCOUNT CODE UPGRADE ATTACHMENT
// ================================================================================================

/// A [`NoteAttachment`] that carries an [`AccountCodeUpgrade`], so that a transaction consuming the
/// note can upgrade an account to its code.
///
/// The attachment content is the encoding of [`AccountCodeUpgrade::to_elements`], which is
/// also the value of the upgrade's advice map entry.
///
/// When the kernel initializes an upgrade that the advice map does not provide the code for, the
/// transaction host looks for an attachment of this scheme on the input notes whose code matches
/// the new code commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCodeUpgradeAttachment {
    code_upgrade: AccountCodeUpgrade,
}

impl AccountCodeUpgradeAttachment {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The standardized scheme of [`AccountCodeUpgradeAttachment`]s.
    pub const ATTACHMENT_SCHEME: NoteAttachmentScheme =
        StandardNoteAttachment::AccountCodeUpgrade.attachment_scheme();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [`AccountCodeUpgradeAttachment`] that carries `code_upgrade`.
    pub fn new(code_upgrade: AccountCodeUpgrade) -> Self {
        Self { code_upgrade }
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
}

impl TryFrom<&AccountCodeUpgradeAttachment> for NoteAttachment {
    type Error = AccountCodeUpgradeAttachmentError;

    fn try_from(attachment: &AccountCodeUpgradeAttachment) -> Result<Self, Self::Error> {
        // The encoding is padded to whole words, so there is no remainder.
        let elements = attachment.code_upgrade.to_elements();
        let words: Vec<Word> = elements
            .as_chunks::<{ Word::NUM_ELEMENTS }>()
            .0
            .iter()
            .map(|word_elements| Word::new(*word_elements))
            .collect();

        NoteAttachment::with_words(AccountCodeUpgradeAttachment::ATTACHMENT_SCHEME, words)
            .map_err(AccountCodeUpgradeAttachmentError::CodeTooLarge)
    }
}

impl TryFrom<&NoteAttachment> for AccountCodeUpgradeAttachment {
    type Error = AccountCodeUpgradeAttachmentError;

    fn try_from(attachment: &NoteAttachment) -> Result<Self, Self::Error> {
        if attachment.attachment_scheme() != Self::ATTACHMENT_SCHEME {
            return Err(AccountCodeUpgradeAttachmentError::AttachmentSchemeMismatch(
                attachment.attachment_scheme(),
            ));
        }

        AccountCodeUpgrade::try_from_elements(attachment.as_elements())
            .map(Self::new)
            .map_err(AccountCodeUpgradeAttachmentError::DecodeCode)
    }
}

// ACCOUNT CODE UPGRADE ATTACHMENT ERROR
// ================================================================================================

/// Errors that can occur when converting between [`AccountCodeUpgradeAttachment`] and
/// [`NoteAttachment`].
#[derive(Debug, thiserror::Error)]
pub enum AccountCodeUpgradeAttachmentError {
    #[error(
        "attachment scheme {0} did not match expected type {expected}",
        expected = AccountCodeUpgradeAttachment::ATTACHMENT_SCHEME
    )]
    AttachmentSchemeMismatch(NoteAttachmentScheme),
    #[error("failed to decode the account code of the attachment")]
    DecodeCode(#[source] DeserializationError),
    #[error("account code does not fit into a note attachment")]
    CodeTooLarge(#[source] NoteError),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::{AccountCode, AccountCodeUpgrade};
    use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme};

    use super::{AccountCodeUpgradeAttachment, AccountCodeUpgradeAttachmentError};

    #[test]
    fn attachment_roundtrips() -> anyhow::Result<()> {
        let code_upgrade = AccountCodeUpgrade::new(AccountCode::mock());
        let attachment = AccountCodeUpgradeAttachment::new(code_upgrade.clone());

        let note_attachment = NoteAttachment::try_from(&attachment)?;

        // The attachment carries the same encoding as the upgrade's advice map entry.
        let (_, advice_map_value) = code_upgrade.to_advice_map_entry();
        assert_eq!(note_attachment.as_elements(), advice_map_value.as_slice());
        assert_eq!(AccountCodeUpgradeAttachment::try_from(&note_attachment)?, attachment);

        Ok(())
    }

    #[test]
    fn attachment_with_other_scheme_is_rejected() -> anyhow::Result<()> {
        let attachment = NoteAttachment::try_from(&AccountCodeUpgradeAttachment::new(
            AccountCodeUpgrade::new(AccountCode::mock()),
        ))?;
        let other_scheme = NoteAttachmentScheme::new(64)?;
        let other_attachment = NoteAttachment::new(other_scheme, attachment.content().clone());

        assert_matches!(
            AccountCodeUpgradeAttachment::try_from(&other_attachment),
            Err(AccountCodeUpgradeAttachmentError::AttachmentSchemeMismatch(scheme))
                if scheme == other_scheme
        );

        Ok(())
    }
}
