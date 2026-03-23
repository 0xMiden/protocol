use miden_protocol::{Felt, Word};

use super::types::{AmountLimits, OracleId, TierThresholds};

/// Configures the spending-based approval escalation rules used by smart multisig accounts.
///
/// This bundles the tracked spending window, the amount breakpoints used to derive a spending
/// tier, and the approval threshold required for each tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpendingPolicyConfig {
    /// Number of blocks over which spending is accumulated before the tracker resets.
    spending_window: u32,
    /// Spending breakpoints that map accumulated spend into tiers `0..=3`.
    amount_limits: AmountLimits,
    /// Signature thresholds required for each spending tier.
    tier_thresholds: TierThresholds,
}

impl SpendingPolicyConfig {
    pub const fn new(
        spending_window: u32,
        amount_limits: AmountLimits,
        tier_thresholds: TierThresholds,
    ) -> Self {
        Self {
            spending_window,
            amount_limits,
            tier_thresholds,
        }
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

/// Configures the proposal delay rules used by smart multisig timelock flows.
///
/// `min_delay` defines how long a proposal must wait before execution, while
/// `propose_expiration_delta` controls the transaction expiration delta applied to proposal
/// transactions.
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

/// Configures the oracle reader used to normalize asset values during spending-policy checks.
///
/// `oracle_id` selects the logical oracle feed, and `get_price_proc_root` identifies the foreign
/// procedure that should be invoked to fetch a price for a tracked asset.
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
        Self::new(OracleId::new(Felt::new(0), Felt::new(0)), Word::empty())
    }
}
