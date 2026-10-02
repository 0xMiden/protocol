use alloc::boxed::Box;
use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_standards::note::{FeeSponsorshipNote, NoteConsumptionStatus};

use super::bundle::NoteBundle;
use super::checker_utils::{FailedNote, NoteFailure};

// SPONSORSHIP REJECTION
// ================================================================================================

/// The reason a FEE_SPONSORSHIP note cannot be consumed, decided without executing it.
///
/// Reported as the reason of a [`NoteFailure::Rejected`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SponsorshipRejection {
    /// The sponsorship is funded with an asset other than the one the account collects fees in.
    #[error(
        "FEE_SPONSORSHIP note is funded with asset {actual} rather than the asset {expected} the account collects fees in"
    )]
    WrongFeeAsset { expected: AssetId, actual: AssetId },
    /// The feature note is absent, so the sponsorship can only be reclaimed, and the account is not
    /// its reclaimer.
    #[error(
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed, but the native account {native_account} is not the reclaimer account {reclaimer}"
    )]
    NotReclaimer {
        native_account: AccountId,
        reclaimer: AccountId,
    },
    /// The feature note is absent, so the sponsorship can only be reclaimed, and reclaim is
    /// disabled.
    #[error(
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed, and reclaim is disabled"
    )]
    ReclaimDisabled,
    /// The feature note is absent, so the sponsorship can only be reclaimed, and the reclaim height
    /// has not been reached.
    #[error(
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed: reclaim block is {reclaim_height}, but the current block is {current_height}"
    )]
    ReclaimHeightNotReached {
        reclaim_height: BlockNumber,
        current_height: BlockNumber,
    },
    /// The note the sponsorship names as its feature note is itself a FEE_SPONSORSHIP note.
    #[error(
        "FEE_SPONSORSHIP note names note {feature_note_id} as its feature note, but that note is itself a FEE_SPONSORSHIP note"
    )]
    FeatureNoteIsSponsorship { feature_note_id: NoteId },
}

/// Rejects the FEE_SPONSORSHIP notes heading a bundle of their own that `native_account_id` cannot
/// reclaim at `block_ref`.
///
/// This procedure checks that:
/// - Reclaim is enabled.
/// - Reclaim height has been reached.
/// - Reclaiming account is the reclaimer.
pub(super) fn reject_unreclaimable_sponsorships(
    bundles: &[NoteBundle],
    native_account_id: AccountId,
    block_ref: BlockNumber,
) -> Vec<FailedNote> {
    bundles
        .iter()
        .filter_map(|bundle| {
            let head = bundle.head();
            let sponsorship = FeeSponsorshipNote::try_from(head).ok()?;
            let reason = reject_orphan_sponsorship(&sponsorship, native_account_id, block_ref)?;

            Some(FailedNote::new(head.clone(), NoteFailure::from(reason)))
        })
        .collect()
}

/// Returns the consumption status of a lone FEE_SPONSORSHIP note, or `None` if `note` is not one.
///
/// A note checked on its own is one whose feature note is absent, so the reclaim rules of
/// [`reject_unreclaimable_sponsorships`] decide it.
pub(super) fn sponsorship_consumption_status(
    note: &Note,
    native_account_id: AccountId,
    block_ref: BlockNumber,
) -> Option<NoteConsumptionStatus> {
    let sponsorship = FeeSponsorshipNote::try_from(note).ok()?;

    let status = match reject_orphan_sponsorship(&sponsorship, native_account_id, block_ref) {
        None => NoteConsumptionStatus::ConsumableWithAuthorization,
        Some(SponsorshipRejection::ReclaimHeightNotReached { reclaim_height, .. }) => {
            NoteConsumptionStatus::ConsumableAfter(reclaim_height)
        },
        Some(reason) => NoteConsumptionStatus::NeverConsumable(Box::new(reason)),
    };

    Some(status)
}

/// Returns why `sponsorship` cannot be reclaimed by `native_account_id` at `block_ref`, or `None`
/// if it can be.
///
/// Mirrors the `miden::standards::note::note_reclaim::assert_reclaimable` procedure the note script
/// takes the reclaim path through.
fn reject_orphan_sponsorship(
    sponsorship: &FeeSponsorshipNote,
    native_account_id: AccountId,
    block_ref: BlockNumber,
) -> Option<SponsorshipRejection> {
    if sponsorship.reclaimer() != native_account_id {
        return Some(SponsorshipRejection::NotReclaimer {
            native_account: native_account_id,
            reclaimer: sponsorship.reclaimer(),
        });
    }

    match sponsorship.reclaim_height() {
        None => Some(SponsorshipRejection::ReclaimDisabled),
        Some(reclaim_height) if block_ref < reclaim_height => {
            Some(SponsorshipRejection::ReclaimHeightNotReached {
                reclaim_height,
                current_height: block_ref,
            })
        },
        Some(_) => None,
    }
}

impl From<SponsorshipRejection> for NoteFailure {
    fn from(rejection: SponsorshipRejection) -> Self {
        NoteFailure::Rejected { reason: Box::new(rejection) }
    }
}
