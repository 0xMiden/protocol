use miden_protocol::account::AccountId;
use miden_protocol::note::{Note, NoteAttachment, NoteMetadata, NoteType};

use crate::note::{NetworkAccountTarget, NetworkAccountTargetError, NoteExecutionHint};

/// A wrapper around a [`Note`] that is guaranteed to target a network account via a
/// [`NetworkAccountTarget`] attachment.
///
/// This represents a note that is specifically targeted at a single network account. In the future,
/// other types of network notes may exist (e.g., SWAP notes that can be consumed by network
/// accounts but are not targeted at a specific one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountTargetNetworkNote {
    note: Note,
}

impl AccountTargetNetworkNote {
    /// Attempts to construct an [`AccountTargetNetworkNote`] from `note`.
    ///
    /// Returns an error if:
    /// - the note is not [`NoteType::Public`].
    /// - the note's attachment cannot be decoded as a [`NetworkAccountTarget`].
    pub fn new(note: Note) -> Result<Self, NetworkAccountTargetError> {
        // Network notes must be public.
        if note.metadata().note_type() != NoteType::Public {
            return Err(NetworkAccountTargetError::NoteNotPublic(note.metadata().note_type()));
        }

        // Validate that the attachment is a valid NetworkAccountTarget.
        NetworkAccountTarget::try_from(note.metadata().attachment())?;
        Ok(Self { note })
    }

    /// Consumes `self` and returns the underlying [`Note`].
    pub fn into_note(self) -> Note {
        self.note
    }

    /// Returns a reference to the underlying [`Note`].
    pub fn as_note(&self) -> &Note {
        &self.note
    }

    /// Returns the [`NoteMetadata`] of the underlying note.
    pub fn metadata(&self) -> &NoteMetadata {
        self.note.metadata()
    }

    /// Returns the target network [`AccountId`].
    pub fn target_account_id(&self) -> AccountId {
        self.target().target_id()
    }

    /// Returns the decoded [`NetworkAccountTarget`] attachment.
    pub fn target(&self) -> NetworkAccountTarget {
        NetworkAccountTarget::try_from(self.note.metadata().attachment())
            .expect("AccountTargetNetworkNote guarantees valid NetworkAccountTarget attachment")
    }

    /// Returns the [`NoteExecutionHint`] from the decoded [`NetworkAccountTarget`] attachment.
    pub fn execution_hint(&self) -> NoteExecutionHint {
        self.target().execution_hint()
    }

    /// Returns the raw [`NoteAttachment`] from the note metadata.
    pub fn attachment(&self) -> &NoteAttachment {
        self.metadata().attachment()
    }

    /// Returns the [`NoteType`] of the underlying note.
    pub fn note_type(&self) -> NoteType {
        self.metadata().note_type()
    }
}

/// Convenience helpers for [`Note`]s that may target a network account.
pub trait NetworkNoteExt {
    /// Returns `true` if this note is public and its attachment decodes as a
    /// [`NetworkAccountTarget`].
    fn is_network_note(&self) -> bool;

    /// Consumes `self` and returns an [`AccountTargetNetworkNote`], or an error if the attachment
    /// is not a valid target.
    fn into_account_target_network_note(
        self,
    ) -> Result<AccountTargetNetworkNote, NetworkAccountTargetError>;
}

impl NetworkNoteExt for Note {
    fn is_network_note(&self) -> bool {
        self.metadata().note_type() == NoteType::Public
            && NetworkAccountTarget::try_from(self.metadata().attachment()).is_ok()
    }

    fn into_account_target_network_note(
        self,
    ) -> Result<AccountTargetNetworkNote, NetworkAccountTargetError> {
        AccountTargetNetworkNote::new(self)
    }
}

impl TryFrom<Note> for AccountTargetNetworkNote {
    type Error = NetworkAccountTargetError;

    fn try_from(note: Note) -> Result<Self, Self::Error> {
        Self::new(note)
    }
}
