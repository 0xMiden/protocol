use alloc::collections::BTreeSet;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};

use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig};
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
    AuthSingleSigAcl::new(pub_key, scheme, config)
}
