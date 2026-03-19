use miden_protocol::Word;

use super::types::{AmountLimits, OracleId, TierThresholds};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpendingPolicyConfig {
    spending_window: u32,
    amount_limits: AmountLimits,
    tier_thresholds: TierThresholds,
}

impl SpendingPolicyConfig {
    pub const fn new(
        spending_window: u32,
        amount_limits: AmountLimits,
        tier_thresholds: TierThresholds,
    ) -> Self {
        Self { spending_window, amount_limits, tier_thresholds }
    }

    pub const fn spending_window(&self) -> u32 {
        self.spending_window
    }

    pub const fn amount_limits(&self) -> AmountLimits {
        self.amount_limits
    }

    pub const fn tier_thresholds(&self) -> TierThresholds {
        self.tier_thresholds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimelockControllerConfig {
    min_delay: u32,
    propose_expiration_delta: u16,
}

impl TimelockControllerConfig {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleReaderConfig {
    oracle_id: OracleId,
    get_price_proc_root: Word,
}

impl OracleReaderConfig {
    pub const fn new(oracle_id: OracleId, get_price_proc_root: Word) -> Self {
        Self { oracle_id, get_price_proc_root }
    }

    pub const fn oracle_id(&self) -> OracleId {
        self.oracle_id
    }

    pub const fn get_price_proc_root(&self) -> Word {
        self.get_price_proc_root
    }
}

impl Default for OracleReaderConfig {
    fn default() -> Self {
        Self::new(OracleId::default(), Word::empty())
    }
}
