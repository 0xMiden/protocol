use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::errors::{AccountIdError, NoteError};
use miden_protocol::note::{
    NoteAttachment,
    NoteAttachmentContent,
    NoteAttachmentKind,
    NoteAttachmentScheme,
};

use crate::note::{NoteExecutionHint, StandardNoteAttachment};

// NETWORK ACCOUNT TARGET
// ================================================================================================

/// A [`NoteAttachment`] for notes targeted at network accounts.
///
/// It can be encoded to and from a [`NoteAttachmentContent::Word`] with the following layout:
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
    ///   [`AccountStorageMode::Network`](miden_protocol::account::AccountStorageMode::Network).
    pub fn new(
        target_id: AccountId,
        exec_hint: NoteExecutionHint,
    ) -> Result<Self, NetworkAccountTargetError> {
        // TODO: Once AccountStorageMode::Network is removed, this should check is_public.
        if !target_id.is_network() {
            return Err(NetworkAccountTargetError::TargetNotNetwork(target_id));
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

        NoteAttachment::new_word(NetworkAccountTarget::ATTACHMENT_SCHEME, word)
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

        match attachment.content() {
            NoteAttachmentContent::Word(word) => {
                let id_suffix = word[0];
                let id_prefix = word[1];
                let exec_hint = word[2];

                let target_id = AccountId::try_from([id_prefix, id_suffix])
                    .map_err(NetworkAccountTargetError::DecodeTargetId)?;

                let exec_hint = NoteExecutionHint::try_from(exec_hint.as_int())
                    .map_err(NetworkAccountTargetError::DecodeExecutionHint)?;

                NetworkAccountTarget::new(target_id, exec_hint)
            },
            _ => Err(NetworkAccountTargetError::AttachmentKindMismatch(
                attachment.content().attachment_kind(),
            )),
        }
    }
}

// NETWORK ACCOUNT TARGET ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum NetworkAccountTargetError {
    #[error("target account ID must be of type network account")]
    TargetNotNetwork(AccountId),
    #[error(
        "attachment scheme {0} did not match expected type {expected}",
        expected = NetworkAccountTarget::ATTACHMENT_SCHEME
    )]
    AttachmentSchemeMismatch(NoteAttachmentScheme),
    #[error(
        "attachment kind {0} did not match expected type {expected}",
        expected = NoteAttachmentKind::Word
    )]
    AttachmentKindMismatch(NoteAttachmentKind),
    #[error("failed to decode target account ID")]
    DecodeTargetId(#[source] AccountIdError),
    #[error("failed to decode execution hint")]
    DecodeExecutionHint(#[source] NoteError),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::AccountStorageMode;
    use miden_protocol::testing::account_id::AccountIdBuilder;

    use super::*;

    #[test]
    fn network_account_target_serde() -> anyhow::Result<()> {
        let id = AccountIdBuilder::new()
            .storage_mode(AccountStorageMode::Network)
            .build_with_rng(&mut rand::rng());
        let network_account_target = NetworkAccountTarget::new(id, NoteExecutionHint::Always)?;
        assert_eq!(
            network_account_target,
            NetworkAccountTarget::try_from(&NoteAttachment::from(network_account_target))?
        );

        Ok(())
    }

    #[test]
    fn network_account_target_fails_on_private_network_target_account() -> anyhow::Result<()> {
        let id = AccountIdBuilder::new()
            .storage_mode(AccountStorageMode::Private)
            .build_with_rng(&mut rand::rng());
        let err = NetworkAccountTarget::new(id, NoteExecutionHint::Always).unwrap_err();

        assert_matches!(
            err,
            NetworkAccountTargetError::TargetNotNetwork(account_id) if account_id == id
        );

        Ok(())
    }
}
