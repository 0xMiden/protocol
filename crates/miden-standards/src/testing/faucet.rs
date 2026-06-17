use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::AccountProcedureRoot;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

use crate::account::access::PausableManager;
use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig};
use crate::account::faucets::FungibleFaucet;
use crate::account::policies::TokenPolicyManager;

/// Returns every authority-gated setter procedure root exported by a fungible faucet account
/// (`mint_and_send`, the metadata setters, the policy setters, and `pause` / `unpause`).
///
/// Under `Authority::AuthControlled` every procedure in this list must require authentication.
/// Useful as a probe set for regression tests: with the empty exempt list returned by
/// [`user_faucet_single_sig_acl`], none of these roots should appear in the exempt map.
pub fn all_authority_gated_setter_roots() -> Vec<AccountProcedureRoot> {
    vec![
        FungibleFaucet::mint_and_send_root(),
        FungibleFaucet::set_max_supply_root(),
        FungibleFaucet::set_description_root(),
        FungibleFaucet::set_logo_uri_root(),
        FungibleFaucet::set_external_link_root(),
        TokenPolicyManager::set_mint_policy_root(),
        TokenPolicyManager::set_burn_policy_root(),
        TokenPolicyManager::set_send_policy_root(),
        TokenPolicyManager::set_receive_policy_root(),
        PausableManager::pause_root(),
        PausableManager::unpause_root(),
    ]
}

/// Convenience constructor for the typical user-account fungible faucet auth component: an
/// [`AuthSingleSigAcl`] with an empty exempt list, so every called account procedure (every
/// authority-gated setter included) requires a signature.
pub fn user_faucet_single_sig_acl(
    pub_key: PublicKeyCommitment,
    scheme: AuthScheme,
) -> Result<AuthSingleSigAcl, AccountError> {
    AuthSingleSigAcl::new(pub_key, scheme, AuthSingleSigAclConfig::new())
}
