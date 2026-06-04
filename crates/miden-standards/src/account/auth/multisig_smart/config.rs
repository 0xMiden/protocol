/// Configures the proposal delay rules used by smart multisig timelock flows.
///
/// `min_delay` defines how long a proposal must wait before execution, while
/// `propose_expiration_delta` controls the transaction expiration delta applied to proposal
/// transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DelayedExecutionPolicy {
    min_delay: u32,
    propose_expiration_delta: u16,
}

impl DelayedExecutionPolicy {
    pub const fn new(min_delay: u32, propose_expiration_delta: u16) -> Self {
        Self { min_delay, propose_expiration_delta }
    }

    pub const fn min_delay(&self) -> u32 {
        self.min_delay
    }

    pub const fn propose_expiration_delta(&self) -> u16 {
        self.propose_expiration_delta
    }
}
