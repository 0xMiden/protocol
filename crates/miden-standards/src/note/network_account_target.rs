use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::errors::{AccountIdError, NoteError};
use miden_protocol::note::{NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteType};

use crate::note::{NoteExecutionHint, StandardNoteAttachment};

// NETWORK ACCOUNT TARGET
// ================================================================================================

/// A [`NoteAttachment`] for notes targeted at network accounts.
///
/// It can be encoded to and from a single-word attachment content with the following layout:
///
/// ```text
/// - 0th felt: [target_id_suffix (56 bits) | 8 zero bits]
/// - 1st felt: [target_id_prefix (64 bits)]
/// - 2nd felt: [24 zero bits | exec_hint_payload (32 bits) | exec_hint_tag (8 bits)]
/// - 3rd felt: [64 zero bits]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAccountTarget {
    target_id: AccountId,
    exec_hint: NoteExecutionHint,
}

impl NetworkAccountTarget {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The standardized scheme of [`NetworkAccountTarget`] attachments.
    pub const ATTACHMENT_SCHEME: NoteAttachmentScheme =
        StandardNoteAttachment::NetworkAccountTarget.attachment_scheme();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NetworkAccountTarget`] from the provided parts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided `target_id` does not have
    ///   [`AccountType::Public`](miden_protocol::account::AccountType::Public).
    pub fn new(
        target_id: AccountId,
        exec_hint: NoteExecutionHint,
    ) -> Result<Self, NetworkAccountTargetError> {
        if !target_id.is_public() {
            return Err(NetworkAccountTargetError::TargetNotPublic(target_id));
        }

        Ok(Self { target_id, exec_hint })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountId`] at which the note is targeted.
    pub fn target_id(&self) -> AccountId {
        self.target_id
    }

    /// Returns the [`NoteExecutionHint`] of the note.
    pub fn execution_hint(&self) -> NoteExecutionHint {
        self.exec_hint
    }
}

impl From<NetworkAccountTarget> for NoteAttachment {
    fn from(network_attachment: NetworkAccountTarget) -> Self {
        let mut word = Word::empty();
        word[0] = network_attachment.target_id.suffix();
        word[1] = network_attachment.target_id.prefix().as_felt();
        word[2] = network_attachment.exec_hint.into();

        NoteAttachment::with_word(NetworkAccountTarget::ATTACHMENT_SCHEME, word)
    }
}

impl TryFrom<&NoteAttachments> for NetworkAccountTarget {
    type Error = NetworkAccountTargetError;

    fn try_from(attachments: &NoteAttachments) -> Result<Self, Self::Error> {
        // Find the first matching attachment. In case of multiple network account target
        // attachments, we pick the first one as the canonical one.
        let attachment = attachments
            .find(NetworkAccountTarget::ATTACHMENT_SCHEME)
            .ok_or_else(|| NetworkAccountTargetError::MissingAttachmentScheme)?;

        Self::try_from(attachment)
    }
}
impl TryFrom<&NoteAttachment> for NetworkAccountTarget {
    type Error = NetworkAccountTargetError;

    fn try_from(attachment: &NoteAttachment) -> Result<Self, Self::Error> {
        if attachment.attachment_scheme() != Self::ATTACHMENT_SCHEME {
            return Err(NetworkAccountTargetError::AttachmentSchemeMismatch(
                attachment.attachment_scheme(),
            ));
        }

        let words = attachment.content().as_words();
        if words.len() != 1 {
            return Err(NetworkAccountTargetError::AttachmentContentNumWordsMismatch(
                attachment.content().num_words(),
            ));
        }
        let word = words[0];

        let id_suffix = word[0];
        let id_prefix = word[1];
        let exec_hint = word[2];

        let target_id = AccountId::try_from_elements(id_suffix, id_prefix)
            .map_err(NetworkAccountTargetError::DecodeTargetId)?;

        let exec_hint = NoteExecutionHint::try_from(exec_hint.as_canonical_u64())
            .map_err(NetworkAccountTargetError::DecodeExecutionHint)?;

        NetworkAccountTarget::new(target_id, exec_hint)
    }
}

// NETWORK ACCOUNT TARGET ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum NetworkAccountTargetError {
    #[error("note attachments do not contain a network account target scheme")]
    MissingAttachmentScheme,
    #[error("target account ID must have public account type")]
    TargetNotPublic(AccountId),
    #[error(
        "attachment scheme {0} did not match expected type {expected}",
        expected = NetworkAccountTarget::ATTACHMENT_SCHEME
    )]
    AttachmentSchemeMismatch(NoteAttachmentScheme),
    #[error("network account target expects attachment content with one word, got {0}")]
    AttachmentContentNumWordsMismatch(u16),
    #[error("failed to decode target account ID")]
    DecodeTargetId(#[source] AccountIdError),
    #[error("failed to decode execution hint")]
    DecodeExecutionHint(#[source] NoteError),
    #[error("network note must be public, but was {0:?}")]
    NoteNotPublic(NoteType),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountType;
    use miden_protocol::testing::account_id::AccountIdBuilder;

    use super::*;

    #[test]
    fn network_account_target_serde() -> anyhow::Result<()> {
        let id = AccountIdBuilder::new()
            .account_type(AccountType::Public)
            .build_with_rng(&mut rand::rng());
        let network_account_target = NetworkAccountTarget::new(id, NoteExecutionHint::Always)?;
        assert_eq!(
            network_account_target,
            NetworkAccountTarget::try_from(&NoteAttachment::from(network_account_target))?
        );

        Ok(())
    }

    #[test]
    fn network_account_target_fails_on_private_target_account() -> anyhow::Result<()> {
        let id = AccountIdBuilder::new()
            .account_type(AccountType::Private)
            .build_with_rng(&mut rand::rng());
        let err = NetworkAccountTarget::new(id, NoteExecutionHint::Always).unwrap_err();

        assert_matches!(
            err,
            NetworkAccountTargetError::TargetNotPublic(account_id) if account_id == id
        );

        Ok(())
    }
}
