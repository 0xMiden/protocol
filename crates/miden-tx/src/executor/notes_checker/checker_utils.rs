use alloc::collections::BTreeMap;
use alloc::vec::Vec;

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

    /// Returns a reference to the error, if this note was the one blamed for the failure. `None`
    /// otherwise.
    pub fn error(&self) -> Option<&TransactionExecutorError> {
        match &self.failure {
            NoteFailure::Blamed { error, .. } => Some(error),
            NoteFailure::Collateral { .. } => None,
        }
    }

    /// Returns the number of cycles consumed before failure, if available.
    ///
    /// This is `Some` when the failure was due to exceeding the cycle limit, and `None`
    /// for other error types where the cycle count is not meaningful.
    pub fn num_cycles(&self) -> Option<usize> {
        match &self.failure {
            NoteFailure::Blamed { num_cycles, .. } => *num_cycles,
            NoteFailure::Collateral { .. } => None,
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
    pub(super) fn group(notes: Vec<Note>) -> Vec<Self> {
        let note_indices: BTreeMap<NoteId, usize> =
            notes.iter().enumerate().map(|(idx, note)| (note.id(), idx)).collect();

        // Put the feature notes and orphan notes to the values with keys equal to this note index
        // in the `note_indices`. Sponsorship notes are appended to the values which contain the
        // corresponding feature note.
        // Keying by index rather than by note ID keeps the bundles in the caller's order.
        let mut bundles: BTreeMap<usize, Vec<Note>> = BTreeMap::new();
        for (idx, note) in notes.into_iter().enumerate() {
            // A sponsorship is only bundled when the note it sponsors is actually an input;
            // otherwise it can only be reclaimed, which is something it has to attempt on its own.
            match FeeSponsorshipNote::try_from(&note)
                .ok()
                .and_then(|sponsorship| note_indices.get(&sponsorship.feature_note_id()).copied())
            {
                Some(head_idx) => bundles.entry(head_idx).or_default().push(note),
                // This note heads its own bundle, so it goes first whichever side of the notes
                // bound to it it arrives on.
                None => bundles.entry(idx).or_default().insert(0, note),
            }
        }

        bundles.into_values().map(|notes| Self { notes }).collect()
    }

    /// Returns the notes forming the bundle.
    pub(super) fn notes(&self) -> &[Note] {
        &self.notes
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
