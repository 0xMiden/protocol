use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

use crate::account::auth::{
    Approver, ApproverSet, AuthGuardedMultisig, AuthGuardedMultisigConfig, AuthMultisig,
    AuthMultisigConfig, AuthSingleSigAcl, AuthSingleSigAclConfig, GuardianConfig,
};
use crate::account::faucets::FungibleFaucet;

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
/// [`AuthMultisig`] over `approvers` with the given `default_threshold`. Every authority-gated
/// setter is protected by that threshold automatically: [`AuthMultisig`] is fail-closed, so a
/// called procedure with no per-procedure override contributes the default threshold and cannot
/// be authorized with fewer signatures. No per-procedure overrides are configured here.
pub fn user_faucet_multisig(
    approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    default_threshold: u32,
) -> Result<AuthMultisig, AccountError> {
    let approvers = approvers
        .iter()
        .map(|(pub_key, auth_scheme)| Approver::new(*pub_key, *auth_scheme))
        .collect();
    let approver_set = ApproverSet::new(approvers, default_threshold)?;
    let config = AuthMultisigConfig::new(approver_set);
    AuthMultisig::new(config)
}

/// Convenience constructor for a guardian-backed multisig user-account fungible faucet auth
/// component: an [`AuthGuardedMultisig`] over `approvers` with the given `default_threshold` and
/// `guardian`. Every authority-gated setter is protected by that threshold automatically:
/// [`AuthGuardedMultisig`] is fail-closed, so a called procedure with no per-procedure override
/// contributes the default threshold and cannot be authorized with fewer signatures. No
/// per-procedure overrides are configured here.
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
    let config = AuthGuardedMultisigConfig::new(approver_set, guardian)?;
    AuthGuardedMultisig::new(config)
}
