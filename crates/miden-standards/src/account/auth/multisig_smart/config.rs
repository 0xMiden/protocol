use miden_protocol::errors::AccountError;

/// Configures the proposal delay rules used by smart multisig timelock flows.
///
/// `min_delay` defines how long a proposal must wait before execution, while
/// `propose_expiration_delta` controls the transaction expiration delta applied to proposal
/// transactions.
///
/// Both fields must be non-zero. The MASM `update_delayed_execution_policy` procedure enforces
/// the same constraint at runtime via `ERR_MIN_DELAY_ZERO` / `ERR_PROPOSE_EXPIRATION_DELTA_ZERO`;
/// Rust-side validation here is the primary check, with the MASM kept as a safety net.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayedExecutionPolicy {
    min_delay: u32,
    propose_expiration_delta: u16,
}

impl DelayedExecutionPolicy {
    /// Creates a new policy after validating that both fields are non-zero.
    pub fn new(min_delay: u32, propose_expiration_delta: u16) -> Result<Self, AccountError> {
        if min_delay == 0 {
            return Err(AccountError::other("delayed execution min_delay must be non-zero"));
        }
        if propose_expiration_delta == 0 {
            return Err(AccountError::other(
                "delayed execution propose_expiration_delta must be non-zero",
            ));
        }
        Ok(Self { min_delay, propose_expiration_delta })
    }

    pub const fn min_delay(&self) -> u32 {
        self.min_delay
    }

    pub const fn propose_expiration_delta(&self) -> u16 {
        self.propose_expiration_delta
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::DelayedExecutionPolicy;

    #[test]
    fn delayed_execution_policy_rejects_zero_min_delay() {
        let err = DelayedExecutionPolicy::new(0, 5).unwrap_err();
        assert!(err.to_string().contains("min_delay must be non-zero"));
    }

    #[test]
    fn delayed_execution_policy_rejects_zero_propose_expiration_delta() {
        let err = DelayedExecutionPolicy::new(30, 0).unwrap_err();
        assert!(err.to_string().contains("propose_expiration_delta must be non-zero"));
    }

    #[test]
    fn delayed_execution_policy_accepts_valid_values() {
        let policy =
            DelayedExecutionPolicy::new(30, 2).expect("non-zero arguments should be accepted");
        assert_eq!(policy.min_delay(), 30);
        assert_eq!(policy.propose_expiration_delta(), 2);
    }
}
