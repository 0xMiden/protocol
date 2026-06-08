use miden_protocol::Word;

use super::types::{AmountLimits, OracleId, TierThresholds};

/// Configures the spending-based approval escalation rules used by smart multisig accounts.
///
/// This bundles the tracked spending window, the amount breakpoints used to derive a spending
/// tier, and the approval threshold required for each tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpendingPolicy {
    /// Number of blocks over which spending is accumulated before the tracker resets.
    spending_window: u32,
    /// Spending breakpoints that map accumulated spend into tiers `0..=3`.
    amount_limits: AmountLimits,
    /// Signature thresholds required for each spending tier.
    tier_thresholds: TierThresholds,
}

impl SpendingPolicy {
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

/// When `get_price` returns `is_tracked = 0`, `compute_spending_amount` uses this policy (stored
/// in the `get_price_untracked_policy` storage slot).
pub const GET_PRICE_UNTRACKED_OMIT: u32 = 0;
/// Reject authentication if any fungible output note is untracked by the oracle reader.
pub const GET_PRICE_UNTRACKED_REJECT: u32 = 1;

/// Configures the oracle reader used to normalize asset values during spending-policy checks.
///
/// `oracle_id` selects the logical oracle feed, and `get_price_proc_root` identifies the foreign
/// procedure that should be invoked to fetch a price for a tracked asset.
///
/// `untracked_price_policy` controls behavior when that procedure returns `is_tracked = 0` for a
/// fungible output (see [`GET_PRICE_UNTRACKED_OMIT`] and [`GET_PRICE_UNTRACKED_REJECT`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleReaderConfig {
    oracle_id: Option<OracleId>,
    get_price_proc_root: Word,
    untracked_price_policy: u32,
}

impl OracleReaderConfig {
    pub const fn new(oracle_id: OracleId, get_price_proc_root: Word) -> Self {
        Self {
            oracle_id: Some(oracle_id),
            get_price_proc_root,
            untracked_price_policy: GET_PRICE_UNTRACKED_OMIT,
        }
    }

    /// Returns the configured oracle id, or `None` when no oracle is attached (default).
    pub const fn oracle_id(&self) -> Option<OracleId> {
        self.oracle_id
    }

    pub const fn get_price_proc_root(&self) -> Word {
        self.get_price_proc_root
    }

    pub const fn untracked_price_policy(&self) -> u32 {
        self.untracked_price_policy
    }

    pub fn with_untracked_price_policy(mut self, untracked_price_policy: u32) -> Self {
        self.untracked_price_policy = untracked_price_policy;
        self
    }
}

impl Default for OracleReaderConfig {
    fn default() -> Self {
        Self {
            oracle_id: None,
            get_price_proc_root: Word::empty(),
            untracked_price_policy: GET_PRICE_UNTRACKED_OMIT,
        }
    }
}
