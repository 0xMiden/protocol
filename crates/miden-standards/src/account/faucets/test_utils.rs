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

/// Builds a policy manager whose active mint policy is owner-gated, so the faucet needs the
/// `Ownable2Step` component the policy reads the owner from.
pub(super) fn owner_only_mint_policy_manager() -> TokenPolicyManager {
    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::owner_only())
        .active_burn_policy(BurnPolicy::allow_all())
        .build()
}

/// Builds a policy manager whose owner-gated burn policy is only a reserved alternative, which
/// `set_burn_policy` can activate at any time on the live faucet.
pub(super) fn reserved_owner_only_burn_policy_manager() -> TokenPolicyManager {
    TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .allowed_burn_policy(BurnPolicy::owner_only())
        .build()
}
