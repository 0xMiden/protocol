use miden_protocol::Word;
use miden_protocol::errors::AccountError;

/// Defines which execution modes a procedure policy supports and the corresponding threshold
/// values for each mode.
///
/// A procedure can require the immediate threshold, the delayed threshold, or support both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedurePolicyExecutionMode {
    ImmediateOnly {
        immediate_threshold: u32,
    },
    DelayOnly {
        delay_threshold: u32,
    },
    ImmediateOrDelay {
        immediate_threshold: u32,
        delay_threshold: u32,
    },
}

/// Note Restrictions on whether transactions that call a procedure may consume input notes
/// or create output notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ProcedurePolicyNoteRestrictions {
    #[default]
    None = 0,
    NoInputNotes = 1,
    NoOutputNotes = 2,
    NoInputOutputNotes = 3,
}

/// Defines a per-procedure multisig policy.
///
/// A procedure policy can override the default multisig threshold for a specific procedure.
/// It consists of:
/// - an execution mode, which determines whether the procedure uses an immediate threshold, a
///   delayed threshold, or both
/// - note restrictions, which limit whether a transaction calling the procedure may consume input
///   notes or create output notes
///
/// In this context:
/// - the immediate threshold is the signature threshold required for direct execution
/// - the delayed threshold is the signature threshold required for delayed execution
///
/// The policy is encoded into the procedure-policy storage word as:
/// `[immediate_threshold, delayed_threshold, note_restrictions, 0]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcedurePolicy {
    execution_mode: ProcedurePolicyExecutionMode,
    note_restrictions: ProcedurePolicyNoteRestrictions,
}

impl ProcedurePolicy {
    /// Creates an explicit procedure policy from an execution mode and note restriction pair.
    ///
    /// Common multisig cases should generally prefer the `with_*_threshold...` helpers and
    /// configure note restrictions afterwards via [`ProcedurePolicy::with_note_restrictions`].
    pub fn new(
        execution_mode: ProcedurePolicyExecutionMode,
        note_restrictions: ProcedurePolicyNoteRestrictions,
    ) -> Result<Self, AccountError> {
        Self::validate_execution_mode(execution_mode)?;
        Ok(Self { execution_mode, note_restrictions })
    }

    pub fn with_immediate_threshold(immediate_threshold: u32) -> Result<Self, AccountError> {
        Self::new(
            ProcedurePolicyExecutionMode::ImmediateOnly { immediate_threshold },
            ProcedurePolicyNoteRestrictions::None,
        )
    }

    pub fn with_delay_threshold(delay_threshold: u32) -> Result<Self, AccountError> {
        Self::new(
            ProcedurePolicyExecutionMode::DelayOnly { delay_threshold },
            ProcedurePolicyNoteRestrictions::None,
        )
    }

    pub fn with_immediate_and_delay_thresholds(
        immediate_threshold: u32,
        delay_threshold: u32,
    ) -> Result<Self, AccountError> {
        Self::new(
            ProcedurePolicyExecutionMode::ImmediateOrDelay { immediate_threshold, delay_threshold },
            ProcedurePolicyNoteRestrictions::None,
        )
    }

    pub const fn with_note_restrictions(
        mut self,
        note_restrictions: ProcedurePolicyNoteRestrictions,
    ) -> Self {
        self.note_restrictions = note_restrictions;
        self
    }

    pub const fn execution_mode(&self) -> ProcedurePolicyExecutionMode {
        self.execution_mode
    }

    pub const fn note_restrictions(&self) -> ProcedurePolicyNoteRestrictions {
        self.note_restrictions
    }

    pub const fn immediate_threshold(&self) -> Option<u32> {
        match self.execution_mode {
            ProcedurePolicyExecutionMode::ImmediateOnly { immediate_threshold } => {
                Some(immediate_threshold)
            },
            ProcedurePolicyExecutionMode::DelayOnly { .. } => None,
            ProcedurePolicyExecutionMode::ImmediateOrDelay { immediate_threshold, .. } => {
                Some(immediate_threshold)
            },
        }
    }

    pub const fn delay_threshold(&self) -> Option<u32> {
        match self.execution_mode {
            ProcedurePolicyExecutionMode::ImmediateOnly { .. } => None,
            ProcedurePolicyExecutionMode::DelayOnly { delay_threshold } => Some(delay_threshold),
            ProcedurePolicyExecutionMode::ImmediateOrDelay { delay_threshold, .. } => {
                Some(delay_threshold)
            },
        }
    }

    fn validate_execution_mode(
        execution_mode: ProcedurePolicyExecutionMode,
    ) -> Result<(), AccountError> {
        match execution_mode {
            ProcedurePolicyExecutionMode::ImmediateOnly { immediate_threshold } => {
                if immediate_threshold == 0 {
                    return Err(AccountError::other(
                        "procedure policy immediate threshold must be at least 1",
                    ));
                }
            },
            ProcedurePolicyExecutionMode::DelayOnly { delay_threshold } => {
                if delay_threshold == 0 {
                    return Err(AccountError::other(
                        "procedure policy delay threshold must be at least 1",
                    ));
                }
            },
            ProcedurePolicyExecutionMode::ImmediateOrDelay {
                immediate_threshold,
                delay_threshold,
            } => {
                if immediate_threshold == 0 || delay_threshold == 0 {
                    return Err(AccountError::other(
                        "immediate and delayed thresholds must both be at least 1",
                    ));
                }
                if delay_threshold > immediate_threshold {
                    return Err(AccountError::other(
                        "delay threshold cannot exceed immediate threshold",
                    ));
                }
            },
        }

        Ok(())
    }

    pub fn to_word(&self) -> Word {
        let immediate_threshold = self.immediate_threshold().unwrap_or(0);
        let delay_threshold = self.delay_threshold().unwrap_or(0);

        Word::from([immediate_threshold, delay_threshold, self.note_restrictions as u32, 0])
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{ProcedurePolicy, ProcedurePolicyNoteRestrictions};

    #[test]
    fn procedure_policy_word_encoding_matches_storage_layout() {
        let policy = ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3)
            .unwrap()
            .with_note_restrictions(ProcedurePolicyNoteRestrictions::NoInputOutputNotes);

        assert_eq!(policy.to_word(), [4u32, 3, 3, 0].into());
    }

    #[test]
    fn procedure_policy_construction_rejects_invalid_combinations() {
        assert!(
            ProcedurePolicy::with_immediate_threshold(0)
                .unwrap_err()
                .to_string()
                .contains("procedure policy immediate threshold must be at least 1")
        );

        assert!(
            ProcedurePolicy::with_immediate_and_delay_thresholds(1, 0)
                .unwrap_err()
                .to_string()
                .contains("immediate and delayed thresholds must both be at least 1")
        );

        assert!(
            ProcedurePolicy::with_immediate_and_delay_thresholds(1, 2)
                .unwrap_err()
                .to_string()
                .contains("delay threshold cannot exceed immediate threshold")
        );
    }

    #[test]
    fn procedure_policy_thresholds_are_exposed_with_getters() {
        let procedure_policy = ProcedurePolicy::with_delay_threshold(2).unwrap();

        assert_eq!(procedure_policy.immediate_threshold(), None);
        assert_eq!(procedure_policy.delay_threshold(), Some(2));
    }

    #[test]
    fn procedure_policy_note_restrictions_are_exposed_with_getters() {
        let procedure_policy = ProcedurePolicy::with_immediate_threshold(2)
            .unwrap()
            .with_note_restrictions(ProcedurePolicyNoteRestrictions::NoInputNotes);

        assert_eq!(
            ProcedurePolicyNoteRestrictions::default(),
            ProcedurePolicyNoteRestrictions::None
        );
        assert_eq!(
            procedure_policy.note_restrictions(),
            ProcedurePolicyNoteRestrictions::NoInputNotes
        );
    }
}
