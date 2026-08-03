use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

use crate::account::auth::{
    Approver,
    ApproverSet,
    AuthGuardedMultisig,
    AuthGuardedMultisigConfig,
    AuthMultisig,
    AuthMultisigConfig,
    GuardianConfig,
};

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
