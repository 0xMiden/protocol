use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use miden_protocol::account::AccountId;
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::errors::AccountError;
use miden_protocol::{Felt, Word, ZERO};

// UNCOVERED ASSET POLICY
// ================================================================================================

/// How a fungible asset the spending budget did not charge is treated.
///
/// An asset is covered when the budget is configured and the asset is either the base asset or one
/// the oracle priced into it. Anything else falls to this policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
#[non_exhaustive]
pub enum UncoveredAssetPolicy {
    /// The asset is not metered.
    Allow = 0,
    /// The transaction fails.
    #[default]
    Reject = 1,
}

impl UncoveredAssetPolicy {
    /// Returns the value the MASM policy stores and compares against.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// SPENDING ORACLE
// ================================================================================================

/// The price oracle a [`SpendingBudget`] prices non-base assets through.
///
/// Prices are read from the oracle account over a foreign procedure call at the transaction's
/// reference block. Foreign state is not revalidated at inclusion, so every oracle read tightens
/// the transaction's expiration delta to `max_block_age`: the transaction is only includable within
/// that many blocks of the block the price came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendingOracle {
    id: AccountId,
    max_block_age: NonZeroU16,
}

impl SpendingOracle {
    pub const fn new(id: AccountId, max_block_age: NonZeroU16) -> Self {
        Self { id, max_block_age }
    }

    pub const fn id(&self) -> AccountId {
        self.id
    }

    pub const fn max_block_age(&self) -> NonZeroU16 {
        self.max_block_age
    }
}

// SPENDING BUDGET
// ================================================================================================

/// The spending budget: one limit denominated in `base_asset`.
///
/// The base asset is charged one to one. Any other fungible asset is charged at the rate the
/// oracle quotes for it, and falls to the [`UncoveredAssetPolicy`] when there is no oracle or the
/// oracle has no rate for it. A budget without an oracle therefore bounds the base asset alone and
/// needs no foreign account inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendingBudget {
    base_asset: AssetId,
    limit: NonZeroU64,
    oracle: Option<SpendingOracle>,
}

impl SpendingBudget {
    /// Creates a budget without an oracle after validating that the base asset is fungible and the
    /// limit fits a fungible asset amount.
    pub fn new(base_asset: AssetId, limit: NonZeroU64) -> Result<Self, AccountError> {
        if !base_asset.composition().is_fungible() {
            return Err(AccountError::other("spending limit base asset must be fungible"));
        }
        if limit.get() > FungibleAsset::MAX_AMOUNT.as_u64() {
            return Err(AccountError::other(
                "spending limit exceeds the maximum fungible asset amount",
            ));
        }
        Ok(Self { base_asset, limit, oracle: None })
    }

    /// Prices non-base assets through the given oracle.
    pub fn with_oracle(mut self, oracle: SpendingOracle) -> Self {
        self.oracle = Some(oracle);
        self
    }

    pub const fn base_asset(&self) -> AssetId {
        self.base_asset
    }

    pub const fn limit(&self) -> NonZeroU64 {
        self.limit
    }

    pub const fn oracle(&self) -> Option<&SpendingOracle> {
        self.oracle.as_ref()
    }
}

// SPENDING LIMITS POLICY
// ================================================================================================

/// Configures the spending limit enforced by the smart multisig auth procedure.
///
/// Every fungible asset a transaction sends out through an output note is priced into the budget's
/// base asset and charged to the budget. The budget resets every `window_blocks` blocks, at
/// `reference_block_num / window_blocks` boundaries. A transaction whose spend would push the
/// budget over its limit fails regardless of how many approvers signed it; the policy never
/// changes the signature threshold.
///
/// While the policy is enabled every transaction of the account expires `window_blocks` blocks
/// after its reference block, capped at the kernel's maximum delta, so a budget cannot be reopened
/// by referencing a block in an idle window.
///
/// An asset that is neither the base asset nor priced by the oracle falls to the
/// [`UncoveredAssetPolicy`]. Non-fungible assets are not metered.
///
/// # Faulty oracle
///
/// An oracle without a rate for an asset makes that asset fall to the policy, and an unavailable
/// oracle fails the transaction, so under [`UncoveredAssetPolicy::Reject`] every non-base asset
/// stops until governance acts. The intended response is to unset the oracle through
/// `update_spending_oracle`: the base asset keeps being charged under the limit and everything
/// else falls to the policy. Switching to another oracle, or to [`UncoveredAssetPolicy::Allow`],
/// is only needed to move other assets.
///
/// # Security
///
/// The limit is only as strong as the policies on the three procedures that edit it:
/// `update_spending_limits_policy`, `update_spending_oracle` and `set_spending_limit`. Without a
/// [`ProcedurePolicy`](super::ProcedurePolicy) of their own each costs the default threshold, so a
/// quorum able to spend is also able to lift the limit first and the limit adds no protection
/// against it. Give them a policy at least as strong as the protection the limit is meant to
/// provide, for example every approver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingLimitsPolicy {
    window_blocks: NonZeroU32,
    uncovered_assets: UncoveredAssetPolicy,
    budget: SpendingBudget,
}

impl SpendingLimitsPolicy {
    /// Creates a policy with the given window length and budget and the default
    /// [`UncoveredAssetPolicy`].
    pub fn new(window_blocks: NonZeroU32, budget: SpendingBudget) -> Self {
        Self {
            window_blocks,
            uncovered_assets: UncoveredAssetPolicy::default(),
            budget,
        }
    }

    /// Sets how assets the budget does not charge are treated.
    pub fn with_uncovered_assets(mut self, policy: UncoveredAssetPolicy) -> Self {
        self.uncovered_assets = policy;
        self
    }

    pub const fn window_blocks(&self) -> NonZeroU32 {
        self.window_blocks
    }

    pub const fn uncovered_assets(&self) -> UncoveredAssetPolicy {
        self.uncovered_assets
    }

    pub const fn budget(&self) -> &SpendingBudget {
        &self.budget
    }

    // STORAGE ENCODING
    // --------------------------------------------------------------------------------------------

    /// `[window_blocks, uncovered_asset_policy, config_generation = 0, 0]`.
    pub(super) fn config_word(&self) -> Word {
        Word::from([self.window_blocks.get(), self.uncovered_assets.as_u32(), 0, 0])
    }

    /// `[oracle_id_suffix, oracle_id_prefix, max_oracle_block_age, 0]`, or the empty word without
    /// an oracle.
    pub(super) fn oracle_word(&self) -> Word {
        match &self.budget.oracle {
            Some(oracle) => Word::from([
                oracle.id.suffix(),
                oracle.id.prefix().as_felt(),
                Felt::from(u32::from(oracle.max_block_age.get())),
                ZERO,
            ]),
            None => Word::empty(),
        }
    }

    /// The base asset id as a word.
    pub(super) fn base_asset_word(&self) -> Word {
        self.budget.base_asset.into()
    }

    /// `[limit, 0, 0, 0]`.
    pub(super) fn limit_word(&self) -> Word {
        let limit = Felt::new(self.budget.limit.get())
            .expect("limit is validated against the fungible asset maximum");
        Word::from([limit, ZERO, ZERO, ZERO])
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_protocol::asset::NonFungibleAsset;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    };

    use super::*;

    fn faucet(id: u128) -> AccountId {
        AccountId::try_from(id).expect("test faucet id should be valid")
    }

    fn window() -> NonZeroU32 {
        NonZeroU32::new(32_768).unwrap()
    }

    fn usdcx() -> AssetId {
        AssetId::new_fungible(faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1))
    }

    fn budget() -> SpendingBudget {
        SpendingBudget::new(usdcx(), NonZeroU64::new(100_000).unwrap()).unwrap()
    }

    #[test]
    fn config_word_encodes_window_and_policy() {
        let policy = SpendingLimitsPolicy::new(window(), budget())
            .with_uncovered_assets(UncoveredAssetPolicy::Allow);
        assert_eq!(policy.config_word(), Word::from([32_768u32, 0, 0, 0]));

        let policy = SpendingLimitsPolicy::new(window(), budget());
        assert_eq!(policy.config_word(), Word::from([32_768u32, 1, 0, 0]));
    }

    #[test]
    fn budget_words_match_the_masm_layout() {
        let oracle = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET);
        let budget =
            budget().with_oracle(SpendingOracle::new(oracle, NonZeroU16::new(32).unwrap()));
        let policy = SpendingLimitsPolicy::new(window(), budget);

        assert_eq!(
            policy.oracle_word(),
            Word::from([oracle.suffix(), oracle.prefix().as_felt(), Felt::from(32u32), ZERO])
        );
        assert_eq!(policy.base_asset_word(), Word::from(usdcx()));
        assert_eq!(policy.limit_word(), Word::from([100_000u32, 0, 0, 0]));
    }

    #[test]
    fn a_budget_without_an_oracle_leaves_the_oracle_word_empty() {
        let policy = SpendingLimitsPolicy::new(window(), budget());

        assert_eq!(policy.oracle_word(), Word::empty());
        assert_eq!(policy.base_asset_word(), Word::from(usdcx()));
        assert_eq!(policy.limit_word(), Word::from([100_000u32, 0, 0, 0]));
    }

    #[test]
    fn a_limit_above_the_max_amount_is_rejected() {
        let too_large = NonZeroU64::new(FungibleAsset::MAX_AMOUNT.as_u64() + 1).unwrap();
        let err = SpendingBudget::new(usdcx(), too_large).unwrap_err();
        assert!(err.to_string().contains("maximum fungible asset amount"));
    }

    #[test]
    fn a_non_fungible_base_asset_is_rejected() {
        let err = SpendingBudget::new(
            NonFungibleAsset::mock(&[1, 2, 3]).id(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be fungible"));
    }
}
