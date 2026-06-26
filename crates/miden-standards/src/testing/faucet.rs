use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::AccountProcedureRoot;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

use crate::account::access::PausableManager;
use crate::account::auth::{
    Approver,
    ApproverSet,
    AuthGuardedMultisig,
    AuthGuardedMultisigConfig,
    AuthMultisig,
    AuthMultisigConfig,
    AuthSingleSigAcl,
    AuthSingleSigAclConfig,
    GuardianConfig,
};
use crate::account::faucets::FungibleFaucet;
use crate::account::policies::TokenPolicyManager;

/// Returns every authority-gated setter procedure root exported by a fungible faucet account
/// (`mint_and_send`, the metadata setters, the policy setters, and `pause` / `unpause`).
///
/// Useful when assigning per-procedure multisig thresholds (see [`user_faucet_multisig`] /
/// [`user_faucet_guarded`]) so every authority-gated setter requires the configured threshold.
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
/// [`AuthSingleSigAcl`] whose exempt set carries only `receive_and_burn`. Every other
/// authority-gated procedure (the metadata setters, the policy setters, `mint_and_send`,
/// `pause` / `unpause`) requires a signature, while a BURN note targeted at the faucet can be
/// consumed without one.
pub fn user_faucet_single_sig_acl(
    pub_key: PublicKeyCommitment,
    scheme: AuthScheme,
) -> AuthSingleSigAcl {
    let exempt_procedures = BTreeSet::from([FungibleFaucet::receive_and_burn_root()]);
    let config = AuthSingleSigAclConfig::new(exempt_procedures)
        .expect("`receive_and_burn` is within MAX_NUM_PROCEDURES");
    AuthSingleSigAcl::new(Approver::new(pub_key, scheme), config)
}

/// Convenience constructor for a multisig user-account fungible faucet auth component: an
/// [`AuthMultisig`] over `approvers` with the given `default_threshold`, with every
/// authority-gated setter (see [`all_authority_gated_setter_roots`]) pinned to that same
/// threshold via per-procedure thresholds.
pub fn user_faucet_multisig(
    approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    default_threshold: u32,
) -> Result<AuthMultisig, AccountError> {
    let approvers = approvers
        .iter()
        .map(|(pub_key, auth_scheme)| Approver::new(*pub_key, *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, default_threshold)?;

    let proc_thresholds = all_authority_gated_setter_roots()
        .into_iter()
        .map(|root| (root, default_threshold))
        .collect();
    let config = AuthMultisigConfig::new(approver_set).with_proc_thresholds(proc_thresholds)?;
    AuthMultisig::new(config)
}

/// Convenience constructor for a guardian-backed multisig user-account fungible faucet auth
/// component: an [`AuthGuardedMultisig`] over `approvers` with the given `default_threshold` and
/// `guardian`, with every authority-gated setter (see [`all_authority_gated_setter_roots`]) pinned
/// to that same threshold via per-procedure thresholds.
pub fn user_faucet_guarded(
    approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    default_threshold: u32,
    guardian: GuardianConfig,
) -> Result<AuthGuardedMultisig, AccountError> {
    let approvers = approvers
        .iter()
        .map(|(pub_key, auth_scheme)| Approver::new(*pub_key, *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, default_threshold)?;

    let proc_thresholds = all_authority_gated_setter_roots()
        .into_iter()
        .map(|root| (root, default_threshold))
        .collect();
    let config = AuthGuardedMultisigConfig::new(approver_set, guardian)?
        .with_proc_thresholds(proc_thresholds)?;
    AuthGuardedMultisig::new(config)
}
