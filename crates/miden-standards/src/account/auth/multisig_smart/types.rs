use miden_protocol::Felt;
use miden_protocol::account::AccountId;

/// Defines the spending breakpoints used by smart multisig spending-policy evaluation.
///
/// `limit_0`, `limit_1`, and `limit_2` partition the tracked spending amount into four approval
/// tiers. `delay_trigger_amount` is checked separately and marks a transaction as requiring the
/// delayed execution lane when the tracked spending amount exceeds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AmountLimits {
    limit_0: u64,
    limit_1: u64,
    limit_2: u64,
    delay_trigger_amount: u64,
}

impl AmountLimits {
    pub const fn new(limit_0: u64, limit_1: u64, limit_2: u64, delay_trigger_amount: u64) -> Self {
        Self {
            limit_0,
            limit_1,
            limit_2,
            delay_trigger_amount,
        }
    }

    pub const fn limit_0(&self) -> u64 {
        self.limit_0
    }

    pub const fn limit_1(&self) -> u64 {
        self.limit_1
    }

    pub const fn limit_2(&self) -> u64 {
        self.limit_2
    }

    pub const fn delay_trigger_amount(&self) -> u64 {
        self.delay_trigger_amount
    }

    pub const fn as_array(&self) -> [u64; 4] {
        [self.limit_0, self.limit_1, self.limit_2, self.delay_trigger_amount]
    }
}

/// Maps each spending tier index to the number of approver signatures required.
///
/// Tier indices `0..=3` are derived from [`AmountLimits`]. These thresholds are expected to be
/// monotonic and must satisfy `tier_0 > 0` and `tier_0 <= tier_1 <= tier_2 <= tier_3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TierThresholds {
    tier_0: u32,
    tier_1: u32,
    tier_2: u32,
    tier_3: u32,
}

impl TierThresholds {
    pub const fn new(tier_0: u32, tier_1: u32, tier_2: u32, tier_3: u32) -> Self {
        Self { tier_0, tier_1, tier_2, tier_3 }
    }

    pub const fn tier_0(&self) -> u32 {
        self.tier_0
    }

    pub const fn tier_1(&self) -> u32 {
        self.tier_1
    }

    pub const fn tier_2(&self) -> u32 {
        self.tier_2
    }

    pub const fn tier_3(&self) -> u32 {
        self.tier_3
    }

    pub const fn as_array(&self) -> [u32; 4] {
        [self.tier_0, self.tier_1, self.tier_2, self.tier_3]
    }
}

/// Identifies the oracle account used by smart multisig price lookups.
///
/// Wrapping [`AccountId`] keeps the felt layout the same as any other account-id reference at the
/// contract level (prefix-suffix word) while preventing arbitrary `(Felt, Felt)` pairs from being
/// passed to the spending-policy pipeline at the Rust level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleId(AccountId);

impl OracleId {
    pub const fn new(account_id: AccountId) -> Self {
        Self(account_id)
    }

    pub fn account_id(&self) -> AccountId {
        self.0
    }

    pub fn prefix(&self) -> Felt {
        self.0.prefix().as_felt()
    }

    pub fn suffix(&self) -> Felt {
        self.0.suffix()
    }

    pub fn as_felt_pair(&self) -> [Felt; 2] {
        [self.prefix(), self.suffix()]
    }
}

impl From<AccountId> for OracleId {
    fn from(account_id: AccountId) -> Self {
        Self(account_id)
    }
}
