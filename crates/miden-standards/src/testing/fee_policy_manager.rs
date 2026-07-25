use miden_protocol::account::AccountId;

use crate::account::fees::{BasicConstantFeePolicy, FeePolicyManager};

impl FeePolicyManager {
    /// Returns a minimal single-policy manager charging fees in `fee_faucet_id`'s asset, for tests
    /// that need a manager to construct an account but do not exercise the fee flow itself.
    ///
    /// Its active policy is a default [`BasicConstantFeePolicy`], which prices only the
    /// standardized network-account note scripts (at 0) and aborts fee estimation for every other
    /// note script root; tests that consume other notes need a policy with a fee schedule instead.
    pub fn mock(fee_faucet_id: AccountId) -> Self {
        FeePolicyManager::builder()
            .fee_faucet_id(fee_faucet_id)
            .active_fee_policy(BasicConstantFeePolicy::new().into())
            .build()
    }
}
