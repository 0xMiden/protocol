use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::error::Error;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_standards::note::{FeeSponsorshipNote, NoteConsumptionStatus, ReclaimError};

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
///
/// The note heading the bundle comes first: a feature note, or a FEE_SPONSORSHIP note whose feature
/// note is absent.
#[derive(Debug)]
pub(super) struct NoteBundle {
    notes: Vec<Note>,
}

impl NoteBundle {
    /// Returns the notes forming the bundle.
    pub(super) fn notes(&self) -> &[Note] {
        &self.notes
    }

    /// Reports every note of the bundle as failed: the note at `blamed_idx` with `failure`, and the
    /// rest as its collateral, since they cannot be consumed without it.
    pub(super) fn failed_notes(&self, blamed_idx: usize, failure: NoteFailure) -> Vec<FailedNote> {
        let blamed_note = &self.notes[blamed_idx];
        let mut failed_notes: Vec<FailedNote> = self
            .notes
            .iter()
            .map(|note| {
                FailedNote::new(
                    note.clone(),
                    NoteFailure::Collateral { blamed_by: blamed_note.id() },
                )
            })
            .collect();
        failed_notes[blamed_idx] = FailedNote::new(blamed_note.clone(), failure);

        failed_notes
    }
}

// NOTE BUNDLES
// ================================================================================================

/// The bundles a set of input notes is checked in.
#[derive(Debug, Default)]
pub(super) struct NoteBundles(Vec<NoteBundle>);

impl NoteBundles {
    /// Returns the bundles.
    pub(super) fn bundles(&self) -> &[NoteBundle] {
        &self.0
    }

    /// Returns `true` if there are no bundles.
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the notes of all bundles, bundle by bundle.
    pub(super) fn to_notes(&self) -> Vec<Note> {
        self.0.iter().flat_map(|bundle| bundle.notes().iter().cloned()).collect()
    }

    /// Removes and returns the bundle at `idx`.
    pub(super) fn remove(&mut self, idx: usize) -> NoteBundle {
        self.0.remove(idx)
    }

    /// Removes and returns the bundle holding the note with `note_id`, or `None` if no bundle
    /// holds it.
    pub(super) fn remove_containing(&mut self, note_id: NoteId) -> Option<NoteBundle> {
        let idx = self
            .0
            .iter()
            .position(|bundle| bundle.notes().iter().any(|note| note.id() == note_id))?;
        Some(self.0.remove(idx))
    }
}

// NOTE BUNDLER
// ================================================================================================

/// Groups input notes into the [`NoteBundles`] they have to be checked in, rejecting the
/// FEE_SPONSORSHIP notes the native account cannot consume along the way.
pub(super) struct NoteBundler {
    /// The account consuming the notes.
    native_account_id: AccountId,
    /// The reference block the notes are consumed at.
    block_ref: BlockNumber,
    /// The asset the native account collects fees in, or `None` for an account that collects no
    /// fees, in which case the asset of a sponsorship is not checked.
    collected_fee_asset_id: Option<AssetId>,
}

impl NoteBundler {
    /// Returns a new [`NoteBundler`] for notes consumed by `native_account_id` at `block_ref`.
    pub(super) fn new(
        native_account_id: AccountId,
        block_ref: BlockNumber,
        collected_fee_asset_id: Option<AssetId>,
    ) -> Self {
        Self {
            native_account_id,
            block_ref,
            collected_fee_asset_id,
        }
    }

    /// Groups `notes` into bundles that must be consumed together, and rejects the FEE_SPONSORSHIP
    /// notes that cannot be consumed.
    ///
    /// A FEE_SPONSORSHIP note joins the bundle of the feature note it sponsors, and every other
    /// note heads a bundle of its own. A sponsorship whose feature note is absent can only be
    /// reclaimed, so it forms a bundle of its own as well, and fails alone rather than dropping the
    /// notes it would otherwise have been grouped with.
    ///
    /// A FEE_SPONSORSHIP note is rejected when:
    /// - its feature note is absent, and the native account cannot reclaim it.
    /// - its feature note is itself a FEE_SPONSORSHIP note.
    /// - its feature note is present, and it carries an asset other than the one the native account
    ///   collects fees in.
    ///
    /// The bundles keep the order of the notes heading them, and the sponsorships in a bundle keep
    /// their relative order.
    pub(super) fn bundle(&self, notes: &[Note]) -> (NoteBundles, Vec<FailedNote>) {
        let note_indices: BTreeMap<NoteId, usize> =
            notes.iter().enumerate().map(|(idx, note)| (note.id(), idx)).collect();
        let mut rejected = Vec::new();

        // Each bundle is keyed by the index of the note heading it, which keeps the bundles in the
        // caller's order.
        let mut bundles: BTreeMap<usize, Vec<Note>> = BTreeMap::new();
        for (idx, note) in notes.iter().enumerate() {
            match FeeSponsorshipNote::try_from(note) {
                // A feature note heads its bundle, whichever side of its sponsorships it arrives
                // on.
                Err(_) => bundles.entry(idx).or_default().insert(0, note.clone()),
                Ok(sponsorship) => {
                    match self.sponsorship_bundle_key(&sponsorship, idx, notes, &note_indices) {
                        Ok(bundle_key) => bundles.entry(bundle_key).or_default().push(note.clone()),
                        Err(reason) => {
                            rejected.push(FailedNote::new(note.clone(), NoteFailure::from(reason)))
                        },
                    }
                },
            }
        }

        let bundles = bundles.into_values().map(|notes| NoteBundle { notes }).collect();
        (NoteBundles(bundles), rejected)
    }

    /// Returns the key of the bundle which FEE_SPONSORSHIP note at `idx` in `notes` joins, or why
    /// it cannot be consumed.
    fn sponsorship_bundle_key(
        &self,
        sponsorship: &FeeSponsorshipNote,
        idx: usize,
        notes: &[Note],
        note_indices: &BTreeMap<NoteId, usize>,
    ) -> Result<usize, SponsorshipRejection> {
        match note_indices.get(&sponsorship.feature_note_id()).copied() {
            // The feature note is absent, so the sponsorship can only be reclaimed, on its own.
            None => sponsorship
                .check_reclaim(self.native_account_id, self.block_ref)
                .map(|()| idx)
                .map_err(SponsorshipRejection::NotReclaimable),
            Some(feature_note_idx)
                if FeeSponsorshipNote::try_from(&notes[feature_note_idx]).is_ok() =>
            {
                Err(SponsorshipRejection::FeatureNoteIsSponsorship {
                    feature_note_id: sponsorship.feature_note_id(),
                })
            },
            Some(feature_note_idx) => {
                self.reject_unexpected_fee_asset(sponsorship).map_or(Ok(feature_note_idx), Err)
            },
        }
    }

    /// Returns why `sponsorship` cannot pay for the feature note it is bound to, or `None` if it
    /// can.
    fn reject_unexpected_fee_asset(
        &self,
        sponsorship: &FeeSponsorshipNote,
    ) -> Option<SponsorshipRejection> {
        let expected = self.collected_fee_asset_id?;
        let actual = sponsorship.asset().id();

        (actual != expected).then_some(SponsorshipRejection::WrongFeeAsset { expected, actual })
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
