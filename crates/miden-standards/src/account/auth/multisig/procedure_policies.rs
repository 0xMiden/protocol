use miden_protocol::Word;
use miden_protocol::errors::AccountError;

/// Describes which signature thresholds are available for a procedure policy.
///
/// `immediate_threshold` applies to the direct execution lane, while `delay_threshold` applies
/// to the delayed execute lane. A missing threshold means that lane is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcedurePolicyThresholds {
    pub immediate_threshold: Option<u32>,
    pub delay_threshold: Option<u32>,
}

/// Selects how a protected procedure may be executed and which threshold each lane requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedurePolicyMode {
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

/// Additional transaction-shape constraints that may be imposed on a protected procedure call.
///
/// The note restrictions are encoded into the shared multisig procedure-policy map and may be
/// interpreted by advanced multisig runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ProcedurePolicyNoteRestrictions {
    #[default]
    Any = 0,
    NoInputNotes = 1,
    NoOutputNotes = 2,
    NoInputOutputNotes = 3,
}

/// Additional note-shape constraints that may be imposed on a protected procedure call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcedurePolicyConstraints {
    pub note_restrictions: ProcedurePolicyNoteRestrictions,
}

impl ProcedurePolicyConstraints {
    pub const fn none() -> Self {
        Self {
            note_restrictions: ProcedurePolicyNoteRestrictions::Any,
        }
    }

    pub const fn no_input_notes() -> Self {
        Self {
            note_restrictions: ProcedurePolicyNoteRestrictions::NoInputNotes,
        }
    }

    pub const fn no_output_notes() -> Self {
        Self {
            note_restrictions: ProcedurePolicyNoteRestrictions::NoOutputNotes,
        }
    }

    pub const fn no_input_output_notes() -> Self {
        Self {
            note_restrictions: ProcedurePolicyNoteRestrictions::NoInputOutputNotes,
        }
    }
}

/// Shared per-procedure policy configuration used by multisig account variants.
///
/// The policy is encoded into the canonical procedure-policy storage word as:
/// `[immediate_threshold, delayed_threshold, note_restrictions, 0]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcedurePolicy {
    mode: ProcedurePolicyMode,
    constraints: ProcedurePolicyConstraints,
}

impl ProcedurePolicy {
    /// Creates an explicit policy from a mode/constraint pair.
    ///
    /// Common cases should generally prefer the `with_*_threshold...` helpers and attach
    /// constraints afterwards via [`ProcedurePolicy::with_constraints`].
    pub const fn new(mode: ProcedurePolicyMode, constraints: ProcedurePolicyConstraints) -> Self {
        Self { mode, constraints }
    }

    pub const fn with_immediate_threshold(immediate_threshold: u32) -> Self {
        Self::new(
            ProcedurePolicyMode::ImmediateOnly { immediate_threshold },
            ProcedurePolicyConstraints::none(),
        )
    }

    pub const fn with_delay_threshold(delay_threshold: u32) -> Self {
        Self::new(
            ProcedurePolicyMode::DelayOnly { delay_threshold },
            ProcedurePolicyConstraints::none(),
        )
    }

    pub const fn with_immediate_and_delay_thresholds(
        immediate_threshold: u32,
        delay_threshold: u32,
    ) -> Self {
        Self::new(
            ProcedurePolicyMode::ImmediateOrDelay { immediate_threshold, delay_threshold },
            ProcedurePolicyConstraints::none(),
        )
    }

    pub const fn with_constraints(mut self, constraints: ProcedurePolicyConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    pub const fn mode(&self) -> ProcedurePolicyMode {
        self.mode
    }

    pub const fn constraints(&self) -> ProcedurePolicyConstraints {
        self.constraints
    }

    pub const fn thresholds(&self) -> ProcedurePolicyThresholds {
        match self.mode {
            ProcedurePolicyMode::ImmediateOnly { immediate_threshold } => {
                ProcedurePolicyThresholds {
                    immediate_threshold: Some(immediate_threshold),
                    delay_threshold: None,
                }
            },
            ProcedurePolicyMode::DelayOnly { delay_threshold } => ProcedurePolicyThresholds {
                immediate_threshold: None,
                delay_threshold: Some(delay_threshold),
            },
            ProcedurePolicyMode::ImmediateOrDelay { immediate_threshold, delay_threshold } => {
                ProcedurePolicyThresholds {
                    immediate_threshold: Some(immediate_threshold),
                    delay_threshold: Some(delay_threshold),
                }
            },
        }
    }

    fn assert_valid_shape(&self) -> Result<(), AccountError> {
        match self.mode {
            ProcedurePolicyMode::ImmediateOnly { immediate_threshold } => {
                if immediate_threshold == 0 {
                    return Err(AccountError::other(
                        "procedure policy immediate threshold must be at least 1",
                    ));
                }
            },
            ProcedurePolicyMode::DelayOnly { delay_threshold } => {
                if delay_threshold == 0 {
                    return Err(AccountError::other(
                        "procedure policy delay threshold must be at least 1",
                    ));
                }
            },
            ProcedurePolicyMode::ImmediateOrDelay { immediate_threshold, delay_threshold } => {
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

    pub fn assert_valid_for_num_approvers(&self, num_approvers: u32) -> Result<(), AccountError> {
        let thresholds = self.thresholds();

        self.assert_valid_shape()?;

        if let Some(immediate_threshold) = thresholds.immediate_threshold
            && immediate_threshold > num_approvers
        {
            return Err(AccountError::other(
                "procedure policy immediate threshold cannot exceed number of approvers",
            ));
        }
        if let Some(delay_threshold) = thresholds.delay_threshold
            && delay_threshold > num_approvers
        {
            return Err(AccountError::other(
                "procedure policy delay threshold cannot exceed number of approvers",
            ));
        }

        Ok(())
    }

    pub fn to_word(&self) -> Word {
        let thresholds = self.thresholds();
        let immediate_threshold = thresholds.immediate_threshold.unwrap_or(0);
        let delay_threshold = thresholds.delay_threshold.unwrap_or(0);

        Word::from([
            immediate_threshold,
            delay_threshold,
            self.constraints.note_restrictions as u32,
            0,
        ])
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{
        ProcedurePolicy,
        ProcedurePolicyConstraints,
        ProcedurePolicyNoteRestrictions,
        ProcedurePolicyThresholds,
    };

    #[test]
    fn procedure_policy_word_encoding_matches_storage_layout() {
        let policy = ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3)
            .with_constraints(ProcedurePolicyConstraints::no_input_output_notes());

        assert_eq!(policy.to_word(), [4u32, 3, 3, 0].into());
    }

    #[test]
    fn procedure_policy_validation_rejects_invalid_combinations() {
        let policy_with_zero_immediate_threshold = ProcedurePolicy::with_immediate_threshold(0);
        assert!(
            policy_with_zero_immediate_threshold
                .assert_valid_shape()
                .unwrap_err()
                .to_string()
                .contains("procedure policy immediate threshold must be at least 1")
        );

        let policy_with_zero_delay_threshold =
            ProcedurePolicy::with_immediate_and_delay_thresholds(1, 0);
        assert!(
            policy_with_zero_delay_threshold
                .assert_valid_shape()
                .unwrap_err()
                .to_string()
                .contains("immediate and delayed thresholds must both be at least 1")
        );

        let policy_with_delay_above_immediate_threshold =
            ProcedurePolicy::with_immediate_and_delay_thresholds(1, 2);
        assert!(
            policy_with_delay_above_immediate_threshold
                .assert_valid_shape()
                .unwrap_err()
                .to_string()
                .contains("delay threshold cannot exceed immediate threshold")
        );

        let num_approvers_under_test = 2;
        let policy_exceeding_num_approvers = ProcedurePolicy::with_delay_threshold(3);
        assert!(
            policy_exceeding_num_approvers
                .assert_valid_for_num_approvers(num_approvers_under_test)
                .unwrap_err()
                .to_string()
                .contains("procedure policy delay threshold cannot exceed number of approvers")
        );
    }

    #[test]
    fn procedure_policy_thresholds_are_exposed_with_named_fields() {
        let procedure_policy = ProcedurePolicy::with_delay_threshold(2);

        assert_eq!(
            procedure_policy.thresholds(),
            ProcedurePolicyThresholds {
                immediate_threshold: None,
                delay_threshold: Some(2),
            }
        );
    }

    #[test]
    fn procedure_policy_constraints_expose_named_note_restrictions_values() {
        assert_eq!(
            ProcedurePolicyConstraints::none().note_restrictions,
            ProcedurePolicyNoteRestrictions::Any
        );
        assert_eq!(
            ProcedurePolicyConstraints::no_input_notes().note_restrictions,
            ProcedurePolicyNoteRestrictions::NoInputNotes
        );
        assert_eq!(
            ProcedurePolicyConstraints::no_output_notes().note_restrictions,
            ProcedurePolicyNoteRestrictions::NoOutputNotes
        );
        assert_eq!(
            ProcedurePolicyConstraints::no_input_output_notes().note_restrictions,
            ProcedurePolicyNoteRestrictions::NoInputOutputNotes
        );
    }
}
