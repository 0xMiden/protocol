use miden_protocol::note::NoteAttachmentScheme;

/// The [`NoteAttachmentScheme`]s of standard note attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StandardNoteAttachment {
    /// See [`NetworkAccountTarget`](crate::note::NetworkAccountTarget) for details.
    NetworkAccountTarget,
    /// The attachment scheme used by both PSWAP output notes (payback P2ID + remainder PSWAP).
    /// Carries the word `[amount, order_id, depth, 0]`. See
    /// [`PswapNote`](crate::note::PswapNote) for details.
    PswapAttachment,
}

impl StandardNoteAttachment {
    /// Returns the [`NoteAttachmentScheme`] of the standard attachment.
    pub const fn attachment_scheme(&self) -> NoteAttachmentScheme {
        match self {
            StandardNoteAttachment::NetworkAccountTarget => NoteAttachmentScheme::new_const(2u16),
            StandardNoteAttachment::PswapAttachment => NoteAttachmentScheme::new_const(3u16),
        }
    }
}
