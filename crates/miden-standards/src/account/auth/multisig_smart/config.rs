use miden_protocol::errors::AccountError;

/// Configures the proposal delay rules used by smart multisig timelock flows.
///
/// `propose_expiration_delta` bounds how many blocks after its reference block a proposal
/// transaction stays includable, and `min_delay` is the number of blocks a proposal must then wait
/// before execution. The wait counts from the latest block the proposal can be included in, so a
/// proposer cannot shorten it by referencing a stale block: the proposal unlocks at
/// `reference_block + propose_expiration_delta + min_delay`.
///
/// `cancel_threshold` is the number of approver signatures it takes to cancel a proposal. It is
/// recorded on each proposal when it is proposed, so the proposer has no say in it and a later
/// policy update leaves existing proposals as they were; when a proposal is cancelled it is capped
/// by the approvers that still exist. A low value lets a single approver veto any proposal, a high
/// one makes vetoing a coordinated act. It may not exceed the number of approvers, which
/// [`AuthMultisigSmart::new`](super::AuthMultisigSmart::new) and the on-chain policy update
/// enforce.
///
/// All fields must be non-zero.
///
/// Proposing a delayed transaction requires a single approver signature and only starts the
/// timelock; the number of signatures the delayed action costs is governed by the called
/// procedures' delay threshold, enforced when the proposed transaction executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayedExecutionPolicy {
    min_delay: u32,
    propose_expiration_delta: u16,
    cancel_threshold: u32,
}

impl DelayedExecutionPolicy {
    /// Creates a new policy after validating that all fields are non-zero.
    pub fn new(
        min_delay: u32,
        propose_expiration_delta: u16,
        cancel_threshold: u32,
    ) -> Result<Self, AccountError> {
        if min_delay == 0 {
            return Err(AccountError::other("delayed execution min_delay must be non-zero"));
        }
        if propose_expiration_delta == 0 {
            return Err(AccountError::other(
                "delayed execution propose_expiration_delta must be non-zero",
            ));
        }
        if cancel_threshold == 0 {
            return Err(AccountError::other("delayed execution cancel_threshold must be non-zero"));
        }
        Ok(Self {
            min_delay,
            propose_expiration_delta,
            cancel_threshold,
        })
    }

    pub const fn min_delay(&self) -> u32 {
        self.min_delay
    }

    pub const fn propose_expiration_delta(&self) -> u16 {
        self.propose_expiration_delta
    }

    pub const fn cancel_threshold(&self) -> u32 {
        self.cancel_threshold
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::DelayedExecutionPolicy;

    #[test]
    fn delayed_execution_policy_rejects_zero_min_delay() {
        let err = DelayedExecutionPolicy::new(0, 5, 1).unwrap_err();
        assert!(err.to_string().contains("min_delay must be non-zero"));
    }

    #[test]
    fn delayed_execution_policy_rejects_zero_propose_expiration_delta() {
        let err = DelayedExecutionPolicy::new(30, 0, 1).unwrap_err();
        assert!(err.to_string().contains("propose_expiration_delta must be non-zero"));
    }

    #[test]
    fn delayed_execution_policy_rejects_zero_cancel_threshold() {
        let err = DelayedExecutionPolicy::new(30, 2, 0).unwrap_err();
        assert!(err.to_string().contains("cancel_threshold must be non-zero"));
    }

    #[test]
    fn delayed_execution_policy_accepts_valid_values() {
        let policy =
            DelayedExecutionPolicy::new(30, 2, 1).expect("non-zero arguments should be accepted");
        assert_eq!(policy.min_delay(), 30);
        assert_eq!(policy.propose_expiration_delta(), 2);
        assert_eq!(policy.cancel_threshold(), 1);
    }
}
