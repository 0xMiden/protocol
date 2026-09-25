use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::error::Error;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_standards::note::{FeeSponsorshipNote, NoteConsumptionStatus};

use crate::TransactionExecutorError;

// CONSTANTS
// ================================================================================================

/// Maximum number of notes that can be checked at once.
///
/// Fixed at an amount that should keep each run of note consumption checking to a maximum of ~50ms.
pub const MAX_NUM_CHECKER_NOTES: usize = 20;

// NOTE CONSUMPTION INFO
// ================================================================================================

/// Represents a successfully consumed note along with the number of cycles it took to execute.
#[derive(Debug)]
pub struct SuccessfulNote {
    note: Note,
    num_cycles: usize,
}

impl SuccessfulNote {
    /// Constructs a new `SuccessfulNote`.
    pub fn new(note: Note, num_cycles: usize) -> Self {
        Self { note, num_cycles }
    }

    /// Returns a reference to the note.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// Returns the number of cycles consumed during execution.
    pub fn num_cycles(&self) -> usize {
        self.num_cycles
    }
}

/// Contains the reason why a note is not included in the successful set.
///
/// The variants separate the note the executor blamed from the ones that merely shared its bundle.
#[derive(Debug)]
#[non_exhaustive]
pub enum NoteFailure {
    /// The note the executor blamed for the failure.
    Blamed {
        /// The error the failing execution produced.
        error: TransactionExecutorError,
        /// The number of cycles consumed by the note before it failed.
        ///
        /// This is `Some` when the failure was due to exceeding the cycle limit, and `None` for
        /// other error types where the cycle count is not meaningful.
        num_cycles: Option<usize>,
    },
    /// The note was rejected along with the bundle of the note it is bound to, and may well be
    /// consumable in a different set.
    Collateral {
        /// The blamed note this one shared its bundle with.
        blamed_by: NoteId,
    },
    /// The note was rejected by static analysis and never executed.
    Rejected {
        reason: Box<dyn Error + Send + Sync + 'static>,
    },
}

/// Represents a failed note consumption.
#[derive(Debug)]
pub struct FailedNote {
    note: Note,
    failure: NoteFailure,
}

impl FailedNote {
    /// Constructs a new `FailedNote`.
    pub fn new(note: Note, failure: NoteFailure) -> Self {
        Self { note, failure }
    }

    /// Returns a reference to the note.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// Returns why the note was not consumed.
    pub fn failure(&self) -> &NoteFailure {
        &self.failure
    }

    /// Returns `true` if the executor blamed this note for the failure.
    pub fn is_blamed(&self) -> bool {
        matches!(self.failure, NoteFailure::Blamed { .. })
    }

    /// Returns `true` if this note was rejected along with the bundle of the note it is bound to.
    ///
    /// This is not the negation of [`FailedNote::is_blamed`]: [`NoteFailure`] is non-exhaustive, so
    /// a note may in future fail for a reason that is neither.
    pub fn is_collateral(&self) -> bool {
        matches!(self.failure, NoteFailure::Collateral { .. })
    }

    /// Returns `true` if this note was rejected by static analysis, without being executed.
    pub fn is_rejected(&self) -> bool {
        matches!(self.failure, NoteFailure::Rejected { .. })
    }

    /// Returns a reference to the error, if this note was the one blamed for the failure. `None`
    /// otherwise.
    pub fn execution_error(&self) -> Option<&TransactionExecutorError> {
        match &self.failure {
            NoteFailure::Blamed { error, .. } => Some(error),
            NoteFailure::Collateral { .. } | NoteFailure::Rejected { .. } => None,
        }
    }

    /// Returns the number of cycles consumed before failure, if available.
    ///
    /// This is `Some` when the failure was due to exceeding the cycle limit, and `None`
    /// for other error types where the cycle count is not meaningful.
    pub fn num_cycles(&self) -> Option<usize> {
        match &self.failure {
            NoteFailure::Blamed { num_cycles, .. } => *num_cycles,
            NoteFailure::Collateral { .. } | NoteFailure::Rejected { .. } => None,
        }
    }
}

/// Contains information about the successful and failed consumption of notes.
#[derive(Default, Debug)]
pub struct NoteConsumptionInfo {
    successful: Vec<SuccessfulNote>,
    failed: Vec<FailedNote>,
}

impl NoteConsumptionInfo {
    /// Creates a new [`NoteConsumptionInfo`] instance with the given successful notes.
    pub fn new_successful(successful: Vec<SuccessfulNote>) -> Self {
        Self { successful, ..Default::default() }
    }

    /// Creates a new [`NoteConsumptionInfo`] instance with the given successful and failed notes.
    pub fn new(successful: Vec<SuccessfulNote>, failed: Vec<FailedNote>) -> Self {
        Self { successful, failed }
    }

    /// Returns a reference to the successfully consumed notes.
    pub fn successful(&self) -> &[SuccessfulNote] {
        &self.successful
    }

    /// Returns a reference to the failed notes.
    pub fn failed(&self) -> &[FailedNote] {
        &self.failed
    }

    /// Consumes the struct and returns the successful and failed notes.
    pub fn into_parts(self) -> (Vec<SuccessfulNote>, Vec<FailedNote>) {
        (self.successful, self.failed)
    }
}

// NOTE BUNDLE
// ================================================================================================

/// A group of input notes that has to be tested for consumability as a unit, such as a feature note
/// and the notes which sponsor it.
#[derive(Debug)]
pub(super) struct NoteBundle {
    notes: Vec<Note>,
}

impl NoteBundle {
    /// Groups `notes` into bundles that must be consumed together.
    ///
    /// A FEE_SPONSORSHIP note joins the bundle of the feature note it sponsors; an unpaired
    /// sponsorship note forms a bundle of its own, so that it fails alone rather than dropping the
    /// notes it would otherwise have been grouped with. Every other note type forms a bundle of its
    /// own.
    ///
    /// The feature note is always first in the resulting bundle (if any); bundle preserves the
    /// relative order of the sponsorship notes in it.
    pub(super) fn group(notes: &[Note]) -> Vec<Self> {
        let note_indices: BTreeMap<NoteId, usize> =
            notes.iter().enumerate().map(|(idx, note)| (note.id(), idx)).collect();

        // Put the feature notes and orphan notes to the values with keys equal to this note index
        // in the `note_indices`. Sponsorship notes are appended to the values which contain the
        // corresponding feature note.
        // Keying by index rather than by note ID keeps the bundles in the caller's order.
        let mut bundles: BTreeMap<usize, Vec<Note>> = BTreeMap::new();
        for (idx, note) in notes.iter().enumerate() {
            // A sponsorship is only bundled when the note it sponsors is actually an input;
            // otherwise it can only be reclaimed, which is something it has to attempt on its own.
            match FeeSponsorshipNote::try_from(note)
                .ok()
                .and_then(|sponsorship| note_indices.get(&sponsorship.feature_note_id()).copied())
            {
                Some(head_idx) => bundles.entry(head_idx).or_default().push(note.clone()),
                // This note heads its own bundle, so it goes first whichever side of the notes
                // bound to it it arrives on.
                None => bundles.entry(idx).or_default().insert(0, note.clone()),
            }
        }

        bundles.into_values().map(|notes| Self { notes }).collect()
    }

    /// Returns the notes forming the bundle.
    pub(super) fn notes(&self) -> &[Note] {
        &self.notes
    }
}

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
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed, but the native account {native_account} is not the reclaimer account {reclaimer}"
    )]
    NotReclaimer {
        native_account: AccountId,
        reclaimer: AccountId,
    },
    #[error(
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed, and reclaim is disabled"
    )]
    ReclaimDisabled,
    #[error(
        "FEE_SPONSORSHIP note whose feature note is absent can only be reclaimed: reclaim block is {reclaim_height}, but the current block is {current_height}"
    )]
    ReclaimHeightNotReached {
        reclaim_height: BlockNumber,
        current_height: BlockNumber,
    },
}

/// Rejects the FEE_SPONSORSHIP notes among `bundles` that `native_account_id` cannot consume at
/// `block_ref`.
///
/// This procedure checks the following:
/// - If a bundle has only a sponsorship note. In that case the note can only be reclaimed, which
///   requires reclaim to be enabled, its height to have been reached, and the reclaiming account to
///   be the named reclaimer. The asset a reclaim returns is not constrained, so the fee asset is
///   not checked here.
/// - If a bundle contains a feature note. In that case all the sponsorship notes should have the
///   fee asset the account collects fees in.
///
/// `collected_fee_asset_id` is `None` for an account that collects no fees and therefore has no
/// such asset; the fee asset check is then skipped.
pub(super) fn reject_unconsumable_sponsorships(
    bundles: &[NoteBundle],
    native_account_id: AccountId,
    block_ref: BlockNumber,
    collected_fee_asset_id: Option<AssetId>,
) -> Vec<FailedNote> {
    let mut rejected = Vec::new();

    for bundle in bundles {
        let (head, bound_notes) = bundle
            .notes()
            .split_first()
            .expect("a bundle holds at least the note heading it");

        // A sponsorship only heads a bundle when the feature note it names is not an input.
        if let Ok(sponsorship) = FeeSponsorshipNote::try_from(head) {
            assert!(
                bound_notes.is_empty(),
                "a bundle headed by a sponsorship note should contain only that note"
            );

            if let Some(reason) =
                reject_orphan_sponsorship(&sponsorship, native_account_id, block_ref)
            {
                rejected.push(FailedNote::new(head.clone(), NoteFailure::from(reason)));
            }
        }

        for note in bound_notes {
            // Every note bound to the note heading the bundle is a sponsorship of it.
            if let Ok(sponsorship) = FeeSponsorshipNote::try_from(note)
                && let Some(reason) = reject_bound_sponsorship(&sponsorship, collected_fee_asset_id)
            {
                rejected.push(FailedNote::new(note.clone(), NoteFailure::from(reason)));
            }
        }
    }

    rejected
}

/// Returns the consumption status of a lone FEE_SPONSORSHIP note, or `None` if `note` is not one.
///
/// A note checked on its own is one whose feature note is absent, so the reclaim rules of
/// [`reject_unconsumable_sponsorships`] decide it.
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

/// Returns why `sponsorship` cannot pay for the feature note it is bound to, or `None` if it can.
fn reject_bound_sponsorship(
    sponsorship: &FeeSponsorshipNote,
    collected_fee_asset_id: Option<AssetId>,
) -> Option<SponsorshipRejection> {
    let expected = collected_fee_asset_id?;
    let actual = sponsorship.asset().id();

    (actual != expected).then_some(SponsorshipRejection::WrongFeeAsset { expected, actual })
}

impl From<SponsorshipRejection> for NoteFailure {
    fn from(rejection: SponsorshipRejection) -> Self {
        NoteFailure::Rejected { reason: Box::new(rejection) }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Handle the epilogue error during the note consumption check in the `can_consume` method.
///
/// The goal of this helper function is to handle the cases where the account couldn't consume the
/// note because of some epilogue check failure, e.g. absence of the authenticator.
pub(super) fn handle_epilogue_error(
    epilogue_error: TransactionExecutorError,
) -> NoteConsumptionStatus {
    match epilogue_error {
        // `Unauthorized` is returned for the multisig accounts if the transaction doesn't have
        // enough signatures.
        TransactionExecutorError::Unauthorized(_)
        // `MissingAuthenticator` is returned for the account with the basic auth if the
        // authenticator was not provided to the executor (UnreachableAuth).
        | TransactionExecutorError::MissingAuthenticator => {
            // Both these cases signal that there is a probability that the provided note could be
            // consumed if the authentication is provided.
            NoteConsumptionStatus::ConsumableWithAuthorization
        },
        // TODO: apply additional checks to get the verbose error reason
        _ => NoteConsumptionStatus::UnconsumableConditions,
    }
}
