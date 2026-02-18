use miden_protocol::account::AccountId;
use miden_protocol::note::{Note, NoteAttachment, NoteMetadata, NoteType};

use crate::note::{NetworkAccountTarget, NetworkAccountTargetError};

/// A view over a [`Note`] that is guaranteed to target a network account via a
/// [`NetworkAccountTarget`] attachment.
///
/// This represents a note that is specifically targeted at a network account. In the future,
/// other types of network notes may exist (e.g., SWAP notes that can be consumed by network
/// accounts but are not targeted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkNote<'a> {
    note: &'a Note,
}

impl<'a> NetworkNote<'a> {
    /// Attempts to construct a [`NetworkNote`] view over `note`.
    ///
    /// Returns an error if the note's attachment cannot be decoded as a [`NetworkAccountTarget`].
    pub fn new(note: &'a Note) -> Result<Self, NetworkAccountTargetError> {
        // Validate that the attachment is a valid NetworkAccountTarget
        NetworkAccountTarget::try_from(note.metadata().attachment())?;
        Ok(Self { note })
    }

    /// Returns the underlying [`Note`].
    pub fn as_note(&self) -> &'a Note {
        self.note
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
            .expect("NetworkNote guarantees valid NetworkAccountTarget attachment")
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
    /// Returns `true` if this note's attachment decodes as a [`NetworkAccountTarget`].
    fn is_network_note(&self) -> bool;

    /// Returns a [`NetworkNote`] view, or an error if the attachment is not a valid target.
    fn as_network_note(&self) -> Result<NetworkNote<'_>, NetworkAccountTargetError>;
}

impl NetworkNoteExt for Note {
    fn is_network_note(&self) -> bool {
        NetworkAccountTarget::try_from(self.metadata().attachment()).is_ok()
    }

    fn as_network_note(&self) -> Result<NetworkNote<'_>, NetworkAccountTargetError> {
        NetworkNote::new(self)
    }
}

impl<'a> TryFrom<&'a Note> for NetworkNote<'a> {
    type Error = NetworkAccountTargetError;

    fn try_from(note: &'a Note) -> Result<Self, Self::Error> {
        Self::new(note)
    }
}
