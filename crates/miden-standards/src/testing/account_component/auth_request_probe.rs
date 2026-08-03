use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountComponentCode};
use miden_protocol::utils::sync::LazyLock;

use crate::code_builder::CodeBuilder;

/// MASM for a component whose `emit_auth_request` procedure reproduces the standard authentication
/// procedure's signature request - building a valid transaction summary and emitting the
/// `AUTH_REQUEST` event - but from a regular account procedure that runs outside the epilogue
/// authentication phase.
///
/// It is used to test that the host gates signature *production* to the authentication procedure:
/// when no signature is pre-supplied in the advice provider, the event drives production and must
/// be rejected outside the auth procedure.
const AUTH_REQUEST_PROBE_CODE: &str = "
    use miden::standards::auth
    use {AUTH_REQUEST_EVENT} from miden::protocol::auth

    #! Builds a transaction summary for the (empty) account delta and emits an `AUTH_REQUEST` for it.
    #!
    #! Inputs:  [PK_COMM, scheme_id]
    #! Outputs: []
    @account_procedure
    pub proc emit_auth_request
        # Prepend seven zero user params so the summary layout matches the auth procedure's.
        push.0.0.0.0.0.0.0
        # => [user_params(7), PK_COMM, scheme_id]

        exec.auth::create_tx_summary
        # => [SUMMARY(6 words), PK_COMM, scheme_id]

        exec.auth::hash_and_insert_tx_summary
        # => [MESSAGE, PK_COMM, scheme_id]

        # Reproduces `auth::authenticate_transaction`'s request. With no pre-supplied signature the
        # host must produce one, which is only allowed inside the auth procedure; here it is not.
        emit.AUTH_REQUEST_EVENT

        # Reached only if the request is honored; in the production path the transaction aborts above.
        dropw dropw drop
    end
";

static AUTH_REQUEST_PROBE_PACKAGE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code("mock::auth_request_probe", AUTH_REQUEST_PROBE_CODE)
        .expect("auth request probe code should be valid")
});

/// A mock [`AccountComponent`] used to exercise the host's signature-production gating.
///
/// It exposes a single `emit_auth_request` account procedure that emits an `AUTH_REQUEST` event
/// from outside the authentication procedure. Pair it with an auth component (e.g.
/// [`super::IncrNonceAuthComponent`]) when building an account.
pub struct AuthRequestProbeComponent;

impl AuthRequestProbeComponent {
    /// Returns the compiled component code, so a transaction script can link against it and `call.`
    /// the `emit_auth_request` procedure.
    pub fn code() -> &'static AccountComponentCode {
        &AUTH_REQUEST_PROBE_PACKAGE
    }
}

impl From<AuthRequestProbeComponent> for AccountComponent {
    fn from(_: AuthRequestProbeComponent) -> Self {
        let metadata = AccountComponentMetadata::new("miden::testing::auth_request_probe")
            .with_description(
                "Testing component that emits AUTH_REQUEST outside the auth procedure",
            );

        AccountComponent::new(AUTH_REQUEST_PROBE_PACKAGE.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
