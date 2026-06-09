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
/// Under `Authority::AuthControlled` the auth component must authenticate calls to every
/// procedure in this list, otherwise the setters become permissionless. Use this when
/// constructing a custom [`AuthSingleSigAcl`] trigger procedure list; for the canonical
/// configuration, prefer [`user_faucet_single_sig_acl`].
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
/// [`AuthSingleSigAcl`] with the trigger procedure list set to
/// [`all_authority_gated_setter_roots`] and `allow_unauthorized_input_notes=true`.
///
/// Production callers that need a different ACL shape should construct [`AuthSingleSigAcl`]
/// directly, optionally seeding the trigger list with [`all_authority_gated_setter_roots`].
pub fn user_faucet_single_sig_acl(
    pub_key: PublicKeyCommitment,
    scheme: AuthScheme,
) -> Result<AuthSingleSigAcl, AccountError> {
    AuthSingleSigAcl::new(
        pub_key,
        scheme,
        AuthSingleSigAclConfig::new()
            .with_auth_trigger_procedures(all_authority_gated_setter_roots())
            .with_allow_unauthorized_input_notes(true),
    )
}
