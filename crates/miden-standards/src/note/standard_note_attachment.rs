use miden_protocol::note::NoteAttachmentScheme;

/// The [`NoteAttachmentScheme`]s of standard note attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StandardNoteAttachment {
    /// See [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) for details.
    NetworkAccountTarget,
}

impl StandardNoteAttachment {
    /// Returns the [`NoteAttachmentScheme`] of the standard attachment.
    pub const fn attachment_scheme(&self) -> NoteAttachmentScheme {
        match self {
            StandardNoteAttachment::NetworkAccountTarget => NoteAttachmentScheme::new(1u32),
        }
    }
}
