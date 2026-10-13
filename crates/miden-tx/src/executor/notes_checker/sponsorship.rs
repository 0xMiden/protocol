use alloc::boxed::Box;

use miden_protocol::asset::AssetId;
use miden_protocol::note::NoteId;
use miden_standards::note::ReclaimError;

use super::checker_utils::NoteFailure;

// SPONSORSHIP REJECTION
// ================================================================================================

/// The reason a FEE_SPONSORSHIP note cannot be consumed, decided without executing it.
#[derive(Debug, thiserror::Error)]
pub(super) enum SponsorshipRejection {
    #[error(
        "FEE_SPONSORSHIP note is funded with asset {actual} rather than the asset {expected} the account collects fees in"
    )]
    WrongFeeAsset { expected: AssetId, actual: AssetId },
    #[error(
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed, which the native account cannot do"
    )]
    NotReclaimable(#[source] ReclaimError),
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
