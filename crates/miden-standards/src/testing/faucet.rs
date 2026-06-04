use alloc::vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

use crate::account::access::PausableManager;
use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig};
use crate::account::faucets::FungibleFaucet;
use crate::account::policies::TokenPolicyManager;

/// Convenience constructor for the typical user-account fungible faucet auth component: an
/// [`AuthSingleSigAcl`] with the trigger procedure list covering every authority-gated setter
/// (`mint_and_send`, metadata setters, policy setters, `pause` / `unpause`) and
/// `allow_unauthorized_input_notes=true`.
///
/// Production callers that need a different ACL shape should construct [`AuthSingleSigAcl`]
/// directly.
pub fn user_faucet_single_sig_acl(
    pub_key: PublicKeyCommitment,
    scheme: AuthScheme,
) -> Result<AuthSingleSigAcl, AccountError> {
    let trigger_procedures = vec![
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
    ];
    AuthSingleSigAcl::new(
        pub_key,
        scheme,
        AuthSingleSigAclConfig::new()
            .with_auth_trigger_procedures(trigger_procedures)
            .with_allow_unauthorized_input_notes(true),
    )
}
