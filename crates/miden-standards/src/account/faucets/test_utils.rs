//! Policy-manager fixtures shared by the fungible and non-fungible faucet tests.

use crate::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager, TransferPolicy};

/// Builds a minimal policy manager with AllowAll on every kind, so `has_transfer_policy` is true
/// and the faucet factories must enable asset callbacks.
pub(super) fn allow_all_policy_manager() -> TokenPolicyManager {
    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .active_send_policy(TransferPolicy::allow_all())
        .active_receive_policy(TransferPolicy::allow_all())
        .build()
}

/// Builds a minimal policy manager with AllowAll mint and burn policies and no transfer policy, so
/// `has_transfer_policy` is false and no asset callback slot is installed.
pub(super) fn mint_burn_only_policy_manager() -> TokenPolicyManager {
    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .build()
}
