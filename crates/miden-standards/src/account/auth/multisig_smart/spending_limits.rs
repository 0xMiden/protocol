use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use miden_protocol::account::AccountId;
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::errors::AccountError;
use miden_protocol::{Felt, Word, ZERO};

// UNCOVERED ASSET POLICY
// ================================================================================================

/// How a fungible asset the spending budget did not charge is treated.
///
/// An asset is covered when the budget is configured and the oracle priced the asset into the base
/// asset. Anything else falls to this policy.
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

// SPENDING BUDGET
// ================================================================================================

/// The spending budget: one limit denominated in `base_asset`, charged with every outgoing fungible
/// asset the oracle can price into it.
///
/// Prices are read from the `oracle` account over a foreign procedure call at the transaction's
/// reference block. Foreign state is not revalidated at inclusion, so every oracle read tightens
/// the transaction's expiration delta to `max_oracle_block_age`: the transaction is only includable
/// within that many blocks of the block the price came from. The base asset itself is charged one
/// to one without an oracle call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendingBudget {
    oracle: AccountId,
    base_asset: AssetId,
    max_oracle_block_age: NonZeroU16,
    limit: NonZeroU64,
}

impl SpendingBudget {
    /// Creates a budget after validating that the base asset is fungible and the limit fits a
    /// fungible asset amount.
    pub fn new(
        oracle: AccountId,
        base_asset: AssetId,
        max_oracle_block_age: NonZeroU16,
        limit: NonZeroU64,
    ) -> Result<Self, AccountError> {
        if !base_asset.composition().is_fungible() {
            return Err(AccountError::other("spending limit base asset must be fungible"));
        }
        if limit.get() > FungibleAsset::MAX_AMOUNT.as_u64() {
            return Err(AccountError::other(
                "spending limit exceeds the maximum fungible asset amount",
            ));
        }
        Ok(Self {
            oracle,
            base_asset,
            max_oracle_block_age,
            limit,
        })
    }

    pub const fn oracle(&self) -> AccountId {
        self.oracle
    }

    pub const fn base_asset(&self) -> AssetId {
        self.base_asset
    }

    pub const fn max_oracle_block_age(&self) -> NonZeroU16 {
        self.max_oracle_block_age
    }

    pub const fn limit(&self) -> NonZeroU64 {
        self.limit
    }
}

// SPENDING LIMITS POLICY
// ================================================================================================

/// Configures the spending limit enforced by the smart multisig auth procedure.
///
/// Every fungible asset a transaction sends out through an output note is priced into the budget's
/// base asset through the oracle and charged to the budget. The budget resets every
/// `window_blocks` blocks, at `reference_block_num / window_blocks` boundaries. A transaction whose
/// spend would push the budget over its limit fails regardless of how many approvers signed it; the
/// policy never changes the signature threshold.
///
/// An asset the oracle cannot price falls to the [`UncoveredAssetPolicy`]. Non-fungible assets are
/// not metered.
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

    /// `[oracle_id_suffix, oracle_id_prefix, max_oracle_block_age, 0]`.
    pub(super) fn oracle_word(&self) -> Word {
        Word::from([
            self.budget.oracle.suffix(),
            self.budget.oracle.prefix().as_felt(),
            Felt::from(u32::from(self.budget.max_oracle_block_age.get())),
            ZERO,
        ])
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

    fn budget() -> SpendingBudget {
        let usdcx = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1);
        SpendingBudget::new(
            faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET),
            AssetId::new_fungible(usdcx),
            NonZeroU16::new(32).unwrap(),
            NonZeroU64::new(100_000).unwrap(),
        )
        .unwrap()
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
        let usdcx = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1);
        let policy = SpendingLimitsPolicy::new(window(), budget());

        assert_eq!(
            policy.oracle_word(),
            Word::from([oracle.suffix(), oracle.prefix().as_felt(), Felt::from(32u32), ZERO])
        );
        assert_eq!(policy.base_asset_word(), Word::from(AssetId::new_fungible(usdcx)));
        assert_eq!(policy.limit_word(), Word::from([100_000u32, 0, 0, 0]));
    }

    #[test]
    fn a_limit_above_the_max_amount_is_rejected() {
        let too_large = NonZeroU64::new(FungibleAsset::MAX_AMOUNT.as_u64() + 1).unwrap();
        let usdcx = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1);
        let err = SpendingBudget::new(
            faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET),
            AssetId::new_fungible(usdcx),
            NonZeroU16::new(32).unwrap(),
            too_large,
        )
        .unwrap_err();
        assert!(err.to_string().contains("maximum fungible asset amount"));
    }

    #[test]
    fn a_non_fungible_base_asset_is_rejected() {
        let err = SpendingBudget::new(
            faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET),
            NonFungibleAsset::mock(&[1, 2, 3]).id(),
            NonZeroU16::new(32).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be fungible"));
    }
}
