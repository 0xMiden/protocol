use alloc::boxed::Box;
use alloc::vec::Vec;
use core::error::Error;

use miden_protocol::note::{Note, NoteId};

use super::error::FeeError;
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
