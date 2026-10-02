use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::note::{NoteId, NoteScriptRoot};
use miden_standards::note::FeeSponsorshipNote;

use super::bundle::NoteBundle;
use super::checker_utils::{FailedNote, NoteFailure};
use super::sponsorship::SponsorshipRejection;

// FEE COLLECTION
// ================================================================================================

/// The fee configuration of an account that collects fees, read from its storage.
#[derive(Debug)]
pub(super) struct FeeCollection {
    /// The asset the account collects fees in, which every FEE_SPONSORSHIP note it consumes has to
    /// carry.
    fee_asset_id: AssetId,
    /// The fees the account charges for the feature notes, by script root: `None` for a root the
    /// fee schedule has no entry for. A root missing from the map has a fee that could not be
    /// determined, e.g. because the account prices notes through a custom fee policy.
    scheduled_fees: BTreeMap<NoteScriptRoot, Option<AssetAmount>>,
}

impl FeeCollection {
    /// Returns a new [`FeeCollection`] collecting fees in `fee_asset_id` and charging the
    /// `scheduled_fees` for the feature notes.
    pub(super) fn new(
        fee_asset_id: AssetId,
        scheduled_fees: BTreeMap<NoteScriptRoot, Option<AssetAmount>>,
    ) -> Self {
        Self { fee_asset_id, scheduled_fees }
    }

    /// Rejects the notes among `bundles` that fail the account's fee collection.
    ///
    /// Mirrors the `miden::standards::fees::collect_sponsored_fees` procedure, which prices every
    /// feature note through the account's fee policy and asserts the FEE_SPONSORSHIP notes bound to
    /// it cover that fee. For every bundle headed by a feature note:
    /// - a FEE_SPONSORSHIP note carrying an asset other than the account's fee asset is rejected on
    ///   its own, and does not count towards the fee.
    /// - if the account schedules no fee for the feature note, the whole bundle is rejected, since
    ///   fee estimation aborts for it.
    /// - if the remaining sponsorships do not cover the scheduled fee, the whole bundle is
    ///   rejected. A feature note without sponsorships is covered only by a zero fee.
    ///
    /// A bundle whose fee could not be determined is left for execution to decide.
    pub(super) fn reject_unfunded_bundles(&self, bundles: &[NoteBundle]) -> Vec<FailedNote> {
        let mut rejected = Vec::new();

        for bundle in bundles {
            let feature_note = bundle.head();
            // A bundle headed by a sponsorship is a reclaim, which collects no fee.
            if FeeSponsorshipNote::try_from(feature_note).is_ok() {
                continue;
            }

            // Every note bound to the note heading the bundle is a sponsorship of it.
            let mut funding = Vec::new();
            for note in bundle.bound_notes() {
                let Ok(sponsorship) = FeeSponsorshipNote::try_from(note) else {
                    continue;
                };
                let actual = sponsorship.asset().id();
                if actual != self.fee_asset_id {
                    let reason =
                        SponsorshipRejection::WrongFeeAsset { expected: self.fee_asset_id, actual };
                    rejected.push(FailedNote::new(note.clone(), NoteFailure::from(reason)));
                } else {
                    funding.push((note, sponsorship.asset().amount()));
                }
            }

            let script_root = feature_note.script().root();
            let Some(&scheduled_fee) = self.scheduled_fees.get(&script_root) else {
                continue;
            };
            let reason = match scheduled_fee {
                None => FeeRejection::FeeNotScheduled {
                    feature_note_id: feature_note.id(),
                    script_root,
                },
                Some(required) => {
                    // A total above the maximum asset amount overflows the account vault when it is
                    // collected, which is left for execution to report.
                    let Some(provided) = funding
                        .iter()
                        .try_fold(AssetAmount::ZERO, |total, (_, amount)| (total + *amount).ok())
                    else {
                        continue;
                    };
                    if provided >= required {
                        continue;
                    }
                    FeeRejection::FeeNotCovered {
                        feature_note_id: feature_note.id(),
                        required,
                        provided,
                    }
                },
            };

            // The feature note and its sponsorships only fail together.
            rejected.push(FailedNote::new(feature_note.clone(), NoteFailure::from(reason.clone())));
            for (note, _) in funding {
                rejected.push(FailedNote::new(note.clone(), NoteFailure::from(reason.clone())));
            }
        }

        rejected
    }
}

/// The reason a feature note and the FEE_SPONSORSHIP notes bound to it cannot be consumed, decided
/// without executing them.
///
/// Reported as the reason of a [`NoteFailure::Rejected`], for the feature note and each of its
/// sponsorships alike.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum FeeRejection {
    /// The account schedules no fee for the feature note's script root, so fee estimation aborts
    /// for it.
    #[error(
        "the account schedules no fee for script root {script_root} of feature note {feature_note_id}"
    )]
    FeeNotScheduled {
        feature_note_id: NoteId,
        script_root: NoteScriptRoot,
    },
    /// The FEE_SPONSORSHIP notes bound to the feature note carry less of the fee asset than the
    /// account charges for it.
    #[error(
        "the FEE_SPONSORSHIP notes bound to feature note {feature_note_id} provide a fee of {provided}, but the account charges {required}"
    )]
    FeeNotCovered {
        feature_note_id: NoteId,
        required: AssetAmount,
        provided: AssetAmount,
    },
}

impl From<FeeRejection> for NoteFailure {
    fn from(rejection: FeeRejection) -> Self {
        NoteFailure::Rejected { reason: Box::new(rejection) }
    }
}

/// Returns the script roots of the feature notes heading `bundles`, whose fees are needed to check
/// their bundles with [`FeeCollection::reject_unfunded_bundles`].
pub(super) fn feature_note_roots(bundles: &[NoteBundle]) -> BTreeSet<NoteScriptRoot> {
    bundles
        .iter()
        .map(NoteBundle::head)
        .filter(|head| FeeSponsorshipNote::try_from(*head).is_err())
        .map(|head| head.script().root())
        .collect()
}
