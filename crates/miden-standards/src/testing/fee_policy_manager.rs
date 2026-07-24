use miden_protocol::account::AccountId;

use crate::account::fees::{ConstantFeePolicy, FeePolicyManager};

impl FeePolicyManager {
    /// Returns a minimal single-policy manager charging fees in `fee_faucet_id`'s asset, for tests
    /// that need a manager to construct an account but do not exercise the fee flow itself.
    ///
    /// Its active policy is an empty [`ConstantFeePolicy`], which aborts fee estimation for any
    /// note script root; tests that consume notes need a policy with a fee schedule instead.
    pub fn mock(fee_faucet_id: AccountId) -> Self {
        FeePolicyManager::builder()
            .fee_faucet_id(fee_faucet_id)
            .active_fee_policy(ConstantFeePolicy::new().into())
            .build()
    }
}
