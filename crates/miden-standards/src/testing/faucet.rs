use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::errors::AccountError;

use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig};
use crate::account::faucets::fungible::all_authority_gated_setter_roots;

/// Convenience constructor for the typical user-account fungible faucet auth component: an
/// [`AuthSingleSigAcl`] with the trigger procedure list covering every authority-gated setter
/// and `allow_unauthorized_input_notes=true`.
///
/// Production callers that need a different ACL shape should construct [`AuthSingleSigAcl`]
/// directly.
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
