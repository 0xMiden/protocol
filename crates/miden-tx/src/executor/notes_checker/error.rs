use alloc::boxed::Box;
use alloc::vec::Vec;

use miden_protocol::asset::AssetAmount;
use miden_protocol::note::NoteId;
use miden_standards::note::ReclaimError;

use super::checker_utils::NoteFailure;

// SPONSORSHIP REJECTION ERROR
// ================================================================================================

/// The reason a FEE_SPONSORSHIP note cannot be consumed, decided without executing it.
///
/// Reported as the reason of a [`NoteFailure::Rejected`], so callers can recover it by
/// downcasting the reason.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SponsorshipRejectionError {
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

impl From<SponsorshipRejectionError> for NoteFailure {
    fn from(rejection: SponsorshipRejectionError) -> Self {
        NoteFailure::Rejected { reason: Box::new(rejection) }
    }
}

// FEE ERROR
// ================================================================================================

/// The reason the account could not collect a fee from a note, recovered from the error of the
/// failed execution.
///
/// Reported as the reason of a [`NoteFailure::Fee`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FeeError {
    /// A FEE_SPONSORSHIP note bound to the feature note is funded with an asset other than the one
    /// the account collects fees in.
    #[error(
        "a FEE_SPONSORSHIP note bound to the feature note is funded with an asset other than the one the account collects fees in"
    )]
    WrongFeeAsset,
    /// The account's fee policy has no fee for the feature note, so fee estimation aborted.
    #[error("the account's fee policy has no fee for feature note {feature_note_id}")]
    FeeNotScheduled { feature_note_id: NoteId },
    /// The FEE_SPONSORSHIP notes bound to the feature note carry less than the fee the account
    /// charges for it.
    #[error(
        "the FEE_SPONSORSHIP notes bound to feature note {feature_note_id} provide a fee of {provided}, which does not cover the fee the account charges for it"
    )]
    FeeNotCovered {
        /// The feature note whose fee is not covered.
        feature_note_id: NoteId,
        /// The FEE_SPONSORSHIP notes bound to the feature note.
        sponsorship_ids: Vec<NoteId>,
        /// The fee the FEE_SPONSORSHIP notes provide between them.
        provided: AssetAmount,
        /// The fee the account charges for the feature note, if it could be determined.
        required: Option<AssetAmount>,
    },
}
