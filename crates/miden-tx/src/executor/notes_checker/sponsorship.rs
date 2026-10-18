use alloc::boxed::Box;

use miden_protocol::asset::AssetId;
use miden_protocol::note::NoteId;
use miden_standards::note::ReclaimError;

use super::checker_utils::NoteFailure;

// SPONSORSHIP REJECTION
// ================================================================================================

/// The reason a FEE_SPONSORSHIP note cannot be consumed, decided without executing it.
///
/// Reported as the reason of a [`NoteFailure::Rejected`], so callers can recover it by
/// downcasting the reason.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SponsorshipRejection {
    /// The sponsorship is funded with an asset other than the one the account collects fees in.
    #[error(
        "FEE_SPONSORSHIP note is funded with asset {actual} rather than the asset {expected} the account collects fees in"
    )]
    WrongFeeAsset { expected: AssetId, actual: AssetId },
    /// The feature note is absent, so the sponsorship can only be reclaimed, and the account cannot
    /// reclaim it. [`ReclaimError::ReclaimHeightNotReached`] is the only reason that may pass with
    /// time.
    #[error(
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed, which the native account cannot do"
    )]
    NotReclaimable(#[source] ReclaimError),
    /// The note the sponsorship names as its feature note is itself a FEE_SPONSORSHIP note.
    #[error(
        "FEE_SPONSORSHIP note names note {feature_note_id} as its feature note, but that note is itself a FEE_SPONSORSHIP note"
    )]
    FeatureNoteIsSponsorship { feature_note_id: NoteId },
}

impl From<SponsorshipRejection> for NoteFailure {
    fn from(rejection: SponsorshipRejection) -> Self {
        NoteFailure::Rejected { reason: Box::new(rejection) }
    }
}
