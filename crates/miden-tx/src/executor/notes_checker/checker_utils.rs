use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_processor::ExecutionOptions;
use miden_protocol::note::{Note, NoteId};
use miden_standards::note::{FeeSponsorshipNote, NoteConsumptionStatus};

use crate::TransactionExecutorError;

// CONSTANTS
// ================================================================================================

/// Maximum number of notes that can be checked at once.
///
/// Fixed at an amount that should keep each run of note consumption checking to a maximum of ~50ms.
pub const MAX_NUM_CHECKER_NOTES: usize = 20;

// CHECKER EXECUTION BUDGET
// ================================================================================================

/// Limits the total VM cycle allowance granted across one note consumability check.
pub(super) struct CheckerBudget {
    max_cycles: u32,
    max_cycles_per_attempt: u32,
    remaining_cycles: u32,
}

impl CheckerBudget {
    pub(super) fn new(options: ExecutionOptions) -> Self {
        let max_cycles = options.max_cycles();
        let max_cycles_per_attempt =
            (max_cycles / MAX_NUM_CHECKER_NOTES as u32).max(options.expected_cycles());

        Self {
            max_cycles,
            max_cycles_per_attempt,
            remaining_cycles: max_cycles,
        }
    }

    /// Creates a budget for a single execution that may use the full configured allowance.
    pub(super) fn single_attempt(options: ExecutionOptions) -> Self {
        let max_cycles = options.max_cycles();

        Self {
            max_cycles,
            max_cycles_per_attempt: max_cycles,
            remaining_cycles: max_cycles,
        }
    }

    pub(super) fn max_cycles(&self) -> u32 {
        self.max_cycles
    }

    /// Reserves one conservative execution allowance and returns options capped to that allowance.
    pub(super) fn take_execution_options(
        &mut self,
        options: ExecutionOptions,
    ) -> Option<ExecutionOptions> {
        if self.remaining_cycles < self.max_cycles_per_attempt {
            return None;
        }
        self.remaining_cycles -= self.max_cycles_per_attempt;

        let capped_options = ExecutionOptions::new(
            Some(self.max_cycles_per_attempt),
            options.expected_cycles(),
            options.core_trace_fragment_size(),
        )
        .expect("checker cycle cap must satisfy the source execution options")
        .with_max_advice_size_bytes(options.max_advice_size_bytes())
        .with_max_hash_len_bytes(options.max_hash_len_bytes())
        .with_max_num_continuations(options.max_num_continuations())
        .with_max_stack_depth(options.max_stack_depth())
        .expect("source execution options must contain a valid stack limit")
        .with_max_memory_elements(options.max_memory_elements())
        .with_overlapped_trace_build(options.overlapped_trace_build());

        Some(capped_options)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checker_budget_caps_total_granted_cycles() {
        let options = ExecutionOptions::new(Some(81_920), 4_096, 2_048)
            .unwrap()
            .with_max_advice_size_bytes(123)
            .with_max_hash_len_bytes(456)
            .with_max_num_continuations(7)
            .with_max_stack_depth(32)
            .unwrap()
            .with_max_memory_elements(40)
            .with_overlapped_trace_build(false);
        let mut budget = CheckerBudget::new(options);

        for _ in 0..MAX_NUM_CHECKER_NOTES {
            let attempt_options = budget.take_execution_options(options).unwrap();
            assert_eq!(attempt_options.max_cycles(), 4_096);
            assert_eq!(attempt_options.max_advice_size_bytes(), 123);
            assert_eq!(attempt_options.max_hash_len_bytes(), 456);
            assert_eq!(attempt_options.max_num_continuations(), 7);
            assert_eq!(attempt_options.max_stack_depth(), 32);
            assert_eq!(attempt_options.max_memory_elements(), 40);
            assert!(!attempt_options.overlapped_trace_build());
        }

        assert!(budget.take_execution_options(options).is_none());
    }

    #[test]
    fn single_attempt_budget_preserves_configured_cycle_limit() {
        let options = ExecutionOptions::new(Some(81_920), 4_096, 2_048).unwrap();
        let mut budget = CheckerBudget::single_attempt(options);

        assert_eq!(budget.take_execution_options(options).unwrap().max_cycles(), 81_920);
        assert!(budget.take_execution_options(options).is_none());
    }
}
