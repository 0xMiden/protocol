use alloc::boxed::Box;
use alloc::vec::Vec;
use core::error::Error;

use miden_processor::ExecutionOptions;
use miden_protocol::note::{Note, NoteId};

use super::error::FeeError;
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
    /// The note was rejected by static analysis and never executed.
    Rejected {
        reason: Box<dyn Error + Send + Sync + 'static>,
    },
    /// The account could not collect a fee from the note, which the failed execution was traced to.
    Fee {
        /// Why the fee could not be collected.
        reason: FeeError,
        /// The error the failing execution produced.
        error: TransactionExecutorError,
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
            NoteFailure::Blamed { error, .. } | NoteFailure::Fee { error, .. } => Some(error),
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
            NoteFailure::Collateral { .. }
            | NoteFailure::Rejected { .. }
            | NoteFailure::Fee { .. } => None,
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
