use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use miden_protocol::account::{AccountId, StorageMap, StorageMapKey};
use miden_protocol::asset::{AssetId, FungibleAsset};
use miden_protocol::errors::AccountError;
use miden_protocol::{Felt, Word, ZERO};

// UNCOVERED ASSET POLICY
// ================================================================================================

/// How a fungible asset that no spending budget charged is treated.
///
/// An asset is covered when its faucet has a per-faucet limit or when the oracle priced it into the
/// combined budget. Anything else falls to this policy.
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

// COMBINED SPENDING LIMIT
// ================================================================================================

/// The combined budget: one limit denominated in `base_asset`, charged with every outgoing asset
/// the oracle can price into it.
///
/// Prices are read from the `oracle` account over a foreign procedure call at the transaction's
/// reference block. Foreign state is not revalidated at inclusion, so every oracle read tightens
/// the transaction's expiration delta to `max_oracle_block_age`: the transaction is only includable
/// within that many blocks of the block the price came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CombinedSpendingLimit {
    oracle: AccountId,
    base_asset: AssetId,
    max_oracle_block_age: NonZeroU16,
    limit: NonZeroU64,
}

impl CombinedSpendingLimit {
    /// Creates a combined limit after validating that the base asset is fungible and the limit fits
    /// a fungible asset amount.
    pub fn new(
        oracle: AccountId,
        base_asset: AssetId,
        max_oracle_block_age: NonZeroU16,
        limit: NonZeroU64,
    ) -> Result<Self, AccountError> {
        if !base_asset.composition().is_fungible() {
            return Err(AccountError::other("spending limit base asset must be fungible"));
        }
        validate_limit(limit)?;
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

/// Configures the spending limits enforced by the smart multisig auth procedure.
///
/// Every fungible asset a transaction sends out through an output note is charged to the budget of
/// the faucet that issued it, in the asset's own unit, and, when a combined limit is configured and
/// the oracle can price the asset, to the combined budget in the base asset. Budgets reset every
/// `window_blocks` blocks, at `reference_block_num / window_blocks` boundaries. A transaction whose
/// spend would push any budget over its limit fails regardless of how many approvers signed it; the
/// policy never changes the signature threshold.
///
/// Non-fungible assets are not metered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingLimitsPolicy {
    window_blocks: NonZeroU32,
    uncovered_assets: UncoveredAssetPolicy,
    faucet_limits: Vec<(AccountId, NonZeroU64)>,
    combined: Option<CombinedSpendingLimit>,
}

impl SpendingLimitsPolicy {
    /// Creates a policy with the given window length, the default [`UncoveredAssetPolicy`] and no
    /// budgets.
    pub fn new(window_blocks: NonZeroU32) -> Self {
        Self {
            window_blocks,
            uncovered_assets: UncoveredAssetPolicy::default(),
            faucet_limits: Vec::new(),
            combined: None,
        }
    }

    /// Sets how assets no budget charges are treated.
    pub fn with_uncovered_assets(mut self, policy: UncoveredAssetPolicy) -> Self {
        self.uncovered_assets = policy;
        self
    }

    /// Sets the per-faucet limits, each in the faucet's own unit.
    ///
    /// Rejects duplicate faucets and limits above [`FungibleAsset::MAX_AMOUNT`].
    pub fn with_faucet_limits(
        mut self,
        limits: Vec<(AccountId, NonZeroU64)>,
    ) -> Result<Self, AccountError> {
        let mut faucets = BTreeSet::new();
        for (faucet_id, limit) in &limits {
            if !faucets.insert(*faucet_id) {
                return Err(AccountError::other(
                    "duplicate faucets are not allowed in the spending limits",
                ));
            }
            validate_limit(*limit)?;
        }
        self.faucet_limits = limits;
        Ok(self)
    }

    /// Sets the combined limit.
    pub fn with_combined_limit(mut self, combined: CombinedSpendingLimit) -> Self {
        self.combined = Some(combined);
        self
    }

    pub const fn window_blocks(&self) -> NonZeroU32 {
        self.window_blocks
    }

    pub const fn uncovered_assets(&self) -> UncoveredAssetPolicy {
        self.uncovered_assets
    }

    pub fn faucet_limits(&self) -> &[(AccountId, NonZeroU64)] {
        &self.faucet_limits
    }

    pub const fn combined(&self) -> Option<&CombinedSpendingLimit> {
        self.combined.as_ref()
    }

    /// Returns the key of the given faucet's budget in the spending limits and trackers maps.
    ///
    /// The layout `[faucet_id_suffix, faucet_id_prefix, 0, 0]` matches what
    /// `asset::id_into_faucet_id` leaves on the stack, zero-padded to a word.
    pub fn faucet_key(faucet_id: AccountId) -> StorageMapKey {
        StorageMapKey::new(Word::from([
            faucet_id.suffix(),
            faucet_id.prefix().as_felt(),
            ZERO,
            ZERO,
        ]))
    }

    /// Returns the key of the combined budget in the spending limits and trackers maps.
    ///
    /// An account id is never all zeros, so no faucet key equals it.
    pub fn combined_budget_key() -> StorageMapKey {
        StorageMapKey::empty()
    }

    // STORAGE ENCODING
    // --------------------------------------------------------------------------------------------

    /// `[window_blocks, uncovered_asset_policy, config_generation = 0, 0]`.
    pub(super) fn config_word(&self) -> Word {
        Word::from([self.window_blocks.get(), self.uncovered_assets.as_u32(), 0, 0])
    }

    /// `[oracle_id_suffix, oracle_id_prefix, max_oracle_block_age, 0]`, or the empty word when
    /// no combined limit is configured.
    pub(super) fn oracle_word(&self) -> Word {
        match &self.combined {
            Some(combined) => Word::from([
                combined.oracle.suffix(),
                combined.oracle.prefix().as_felt(),
                Felt::from(u32::from(combined.max_oracle_block_age.get())),
                ZERO,
            ]),
            None => Word::empty(),
        }
    }

    /// The base asset id, or the empty word when no combined limit is configured.
    pub(super) fn base_asset_word(&self) -> Word {
        match &self.combined {
            Some(combined) => combined.base_asset.into(),
            None => Word::empty(),
        }
    }

    /// The spending limits map: one `[limit, 0, 0, 0]` entry per faucet budget plus, when
    /// configured, the combined budget under [`Self::combined_budget_key`].
    pub(super) fn limits_map(&self) -> StorageMap {
        let faucet_entries = self
            .faucet_limits
            .iter()
            .map(|(faucet_id, limit)| (Self::faucet_key(*faucet_id), limit_word(*limit)));
        let combined_entry = self
            .combined
            .as_ref()
            .map(|combined| (Self::combined_budget_key(), limit_word(combined.limit)));

        let entries: Vec<_> = faucet_entries.chain(combined_entry).collect();
        StorageMap::with_entries(entries)
            .expect("spending limit keys are distinct by construction")
    }
}

// HELPERS
// ================================================================================================

fn validate_limit(limit: NonZeroU64) -> Result<(), AccountError> {
    if limit.get() > FungibleAsset::MAX_AMOUNT.as_u64() {
        return Err(AccountError::other(
            "spending limit exceeds the maximum fungible asset amount",
        ));
    }
    Ok(())
}

fn limit_word(limit: NonZeroU64) -> Word {
    let limit =
        Felt::new(limit.get()).expect("limit is validated against the fungible asset maximum");
    Word::from([limit, ZERO, ZERO, ZERO])
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

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

    #[test]
    fn faucet_key_matches_the_masm_layout() {
        let faucet_id = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET);
        let key: Word = SpendingLimitsPolicy::faucet_key(faucet_id).into();
        assert_eq!(key[0], faucet_id.suffix());
        assert_eq!(key[1], faucet_id.prefix().as_felt());
        assert_eq!(key[2], ZERO);
        assert_eq!(key[3], ZERO);
    }

    #[test]
    fn combined_budget_key_is_the_empty_word() {
        assert_eq!(Word::from(SpendingLimitsPolicy::combined_budget_key()), Word::empty());
    }

    #[test]
    fn config_word_encodes_window_and_policy() {
        let policy =
            SpendingLimitsPolicy::new(window()).with_uncovered_assets(UncoveredAssetPolicy::Allow);
        assert_eq!(policy.config_word(), Word::from([32_768u32, 0, 0, 0]));

        let policy = SpendingLimitsPolicy::new(window());
        assert_eq!(policy.config_word(), Word::from([32_768u32, 1, 0, 0]));
    }

    #[test]
    fn faucet_limits_reject_duplicates() {
        let faucet_id = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET);
        let err = SpendingLimitsPolicy::new(window())
            .with_faucet_limits(vec![
                (faucet_id, NonZeroU64::new(1).unwrap()),
                (faucet_id, NonZeroU64::new(2).unwrap()),
            ])
            .unwrap_err();
        assert!(err.to_string().contains("duplicate faucets"));
    }

    #[test]
    fn limits_above_the_max_amount_are_rejected() {
        let too_large = NonZeroU64::new(FungibleAsset::MAX_AMOUNT.as_u64() + 1).unwrap();
        let err = SpendingLimitsPolicy::new(window())
            .with_faucet_limits(vec![(faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET), too_large)])
            .unwrap_err();
        assert!(err.to_string().contains("maximum fungible asset amount"));
    }

    #[test]
    fn limits_map_holds_faucet_and_combined_entries() {
        let usdc = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET);
        let usdcx = faucet(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1);
        let combined = CombinedSpendingLimit::new(
            usdcx,
            AssetId::new_fungible(usdcx),
            NonZeroU16::new(32).unwrap(),
            NonZeroU64::new(100_000).unwrap(),
        )
        .unwrap();
        let policy = SpendingLimitsPolicy::new(window())
            .with_faucet_limits(vec![(usdc, NonZeroU64::new(80_000).unwrap())])
            .unwrap()
            .with_combined_limit(combined);

        let map = policy.limits_map();
        assert_eq!(
            map.get(&SpendingLimitsPolicy::faucet_key(usdc)),
            Word::from([80_000u32, 0, 0, 0])
        );
        assert_eq!(
            map.get(&SpendingLimitsPolicy::combined_budget_key()),
            Word::from([100_000u32, 0, 0, 0])
        );
        assert_eq!(
            policy.oracle_word(),
            Word::from([usdcx.suffix(), usdcx.prefix().as_felt(), Felt::from(32u32), ZERO])
        );
        assert_eq!(policy.base_asset_word(), Word::from(AssetId::new_fungible(usdcx)));
    }

    #[test]
    fn no_combined_limit_leaves_oracle_and_base_asset_empty() {
        let policy = SpendingLimitsPolicy::new(window());
        assert_eq!(policy.oracle_word(), Word::empty());
        assert_eq!(policy.base_asset_word(), Word::empty());
        assert_eq!(policy.limits_map().num_entries(), 0);
    }
}
