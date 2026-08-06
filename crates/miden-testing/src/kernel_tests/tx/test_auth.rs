use anyhow::Context;
use assert_matches::assert_matches;
use miden_processor::ExecutionError;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, Signature};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent};
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::ERR_EPILOGUE_AUTH_PROCEDURE_CALLED_FROM_WRONG_CONTEXT;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_protocol::{Felt, Hasher, ONE, Word, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::{ConditionalAuthComponent, ERR_WRONG_ARGS_MSG};
use miden_standards::testing::mock_account::MockAccountExt;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use miden_tx::{TransactionExecutorError, TransactionKernelError};
use rstest::rstest;

use crate::{Auth, MockChain, TestTransactionBuilder, assert_transaction_executor_error};

pub const ERR_WRONG_ARGS: MasmError = MasmError::from_static_str(ERR_WRONG_ARGS_MSG);

/// Tests that authentication arguments are correctly passed to the auth procedure.
///
/// This test creates an account with a conditional auth component that expects specific
/// auth arguments [97, 98, 99] to not error out. When the correct arguments are provided,
/// the nonce is incremented (because of `incr_nonce_flag`).
#[tokio::test]
async fn test_auth_procedure_args() -> anyhow::Result<()> {
    let account =
        Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, [ConditionalAuthComponent]);

    let auth_args = [
        Felt::new_unchecked(97),
        Felt::new_unchecked(98),
        Felt::new_unchecked(99),
        ONE, // incr_nonce = true
    ];

    let mock_tx = TestTransactionBuilder::new(account).auth_args(auth_args.into()).build()?;

    mock_tx.execute().await.context("failed to execute transaction")?;

    Ok(())
}

/// Tests that incorrect authentication procedure arguments cause transaction execution to fail.
///
/// This test creates an account with a conditional auth component that expects specific
/// auth arguments [97, 98, 99, incr_nonce_flag]. When incorrect arguments are provided
/// (in this case [101, 102, 103]), the transaction should fail with an appropriate error message.
#[tokio::test]
async fn test_auth_procedure_args_wrong_inputs() -> anyhow::Result<()> {
    let account =
        Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, [ConditionalAuthComponent]);

    // The auth script expects [99, 98, 97, nonce_increment_flag]
    let auth_args = [
        ONE, // incr_nonce = true
        Felt::new_unchecked(103),
        Felt::new_unchecked(102),
        Felt::new_unchecked(101),
    ];

    let mock_tx = TestTransactionBuilder::new(account).auth_args(auth_args.into()).build()?;

    let execution_result = mock_tx.execute().await;

    assert_transaction_executor_error!(execution_result, ERR_WRONG_ARGS);

    Ok(())
}

/// Tests that the epilogue's replay guard rejects a user-invoked auth procedure that increments the
/// nonce or makes a direct gated kernel call - the two ways a main-phase invocation sets
/// `was_called[0]`, which the guard reads before running the auth procedure.
///
/// The two cases take different paths: the incrementing body sets `was_called[0]` through
/// `assert_auth_procedure` (unconditional), the non-incrementing body through
/// `authenticate_procedure` for its gated call (tracked because the epilogue-auth-in-progress flag
/// is unset during the main phase). The non-incrementing case is the one a caller-index-based
/// exemption would miss.
///
/// The guard is best-effort: it only fires when the auth procedure reaches the kernel as index 0 (a
/// direct gated call or `incr_nonce`). An auth procedure invoked from user code that does neither -
/// only local MASM, or reaching the kernel via `call.<helper>` (which records the helper's index) -
/// goes undetected. This is benign: the helper is already directly callable from user code so
/// nothing escalates, and the escalation paths stay closed (`incr_nonce` is the only
/// auth-origin-gated procedure and trips the guard, and signature production is rejected
/// host-side).
#[rstest]
#[case::incrementing("exec.native_account::incr_nonce drop")]
#[case::non_incrementing("exec.native_account::get_initial_commitment dropw")]
#[tokio::test]
async fn test_auth_procedure_called_from_wrong_context(
    #[case] auth_body: &str,
) -> anyhow::Result<()> {
    let auth_src = format!(
        "
        use miden::protocol::native_account

        @auth_script
        pub proc auth
            {auth_body}
            # clear the 16-element call frame
            dropw dropw dropw dropw
        end
        "
    );
    let auth_code =
        CodeBuilder::default().compile_component_code("mock::wrong_context_auth", &auth_src)?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("mock::wrong_context_auth"),
    )?;

    let account = AccountBuilder::new([42; 32])
        .with_component(auth_component.clone())
        .with_component(BasicWallet)
        .build_existing()?;

    // A transaction script that invokes the account's auth procedure during the main phase.
    let tx_script_source = "
        @transaction_script
        pub proc main
            call.::mock::wrong_context_auth::auth
        end
    ";
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(auth_component.component_code())?
        .compile_tx_script(tx_script_source)?;

    let mock_tx = TestTransactionBuilder::new(account).tx_script(tx_script).build()?;

    let execution_result = mock_tx.execute().await;

    assert_transaction_executor_error!(
        execution_result,
        ERR_EPILOGUE_AUTH_PROCEDURE_CALLED_FROM_WRONG_CONTEXT
    );

    Ok(())
}

/// Verifies conditional call-tracking end to end: a procedure called from a transaction script
/// (main phase) is tracked, while a procedure called from the auth procedure is not. The auth
/// procedure performs both assertions itself, so a regression fails the transaction.
///
/// Tracking is suppressed for the whole epilogue auth run via the epilogue-auth-in-progress flag,
/// regardless of how the auth procedure reaches the kernel - a caller-index-based exemption
/// (skipping only index 0) would instead track a procedure the auth procedure invokes via `call`.
#[tokio::test]
async fn test_call_tracking_across_tx_script_and_auth_procedure() -> anyhow::Result<()> {
    let component_src = "
        use miden::protocol::native_account

        # called from the transaction script during the main phase -> must be tracked
        @account_procedure
        pub proc proc_from_script
            exec.native_account::get_initial_commitment dropw
        end

        # invoked via `call` from the auth procedure -> must NOT be tracked. uses the SAME gated call
        # as `proc_from_script` (whose positive assertion proves that call is tracked when not
        # suppressed, so this negative assertion is not vacuous), with a trailing no-op to give it a
        # distinct root and hence a distinct was_called flag
        @account_procedure
        pub proc proc_from_auth
            exec.native_account::get_initial_commitment dropw
            push.0 drop
        end

        @auth_script
        pub proc auth
            # invoke `proc_from_auth` via `call` so its gated call is attributed to it (index != 0)
            call.proc_from_auth

            # a procedure called from the auth procedure must NOT be tracked
            procref.proc_from_auth
            exec.native_account::was_procedure_called
            assertz.err=\"procedure called from the auth procedure must not be tracked\"

            # a procedure called from the transaction script must be tracked
            procref.proc_from_script
            exec.native_account::was_procedure_called
            assert.err=\"procedure called from the transaction script must be tracked\"

            # increment the nonce so the transaction changes state and is valid
            exec.native_account::incr_nonce drop

            # clean up the auth args frame
            dropw dropw dropw dropw
        end
    ";
    let component_code =
        CodeBuilder::default().compile_component_code("mock::tracking_auth", component_src)?;
    let component = AccountComponent::new(
        component_code,
        vec![],
        AccountComponentMetadata::mock("mock::tracking_auth"),
    )?;

    let account = AccountBuilder::new([7; 32])
        .with_component(component.clone())
        .with_component(BasicWallet)
        .build_existing()?;

    // The transaction script calls `proc_from_script` during the main phase.
    let tx_script_source = "
        @transaction_script
        pub proc main
            call.::mock::tracking_auth::proc_from_script
        end
    ";
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(component.component_code())?
        .compile_tx_script(tx_script_source)?;

    let mock_tx = TestTransactionBuilder::new(account).tx_script(tx_script).build()?;

    // If either tracking assertion in the auth procedure failed, execution would err.
    mock_tx.execute().await.context("call-tracking regression")?;

    Ok(())
}

/// Regression test: signature production must not be forced from outside the authentication
/// procedure.
///
/// The account exposes an `emit_auth_request` procedure that builds a real transaction summary and
/// emits `AUTH_REQUEST` for it, exactly like the standard auth procedure - but it runs as a normal
/// account procedure invoked from the transaction script, i.e. outside the epilogue authentication
/// phase. No signature is pre-supplied, so the event drives production, which must be rejected with
/// `AuthRequestOutsideAuthProcedure`.
#[tokio::test]
async fn test_auth_request_production_outside_auth_procedure_is_rejected() -> anyhow::Result<()> {
    let probe_code = CodeBuilder::default().compile_component_code(
        "mock::auth_request_probe",
        "
        use miden::standards::auth
        use {AUTH_REQUEST_EVENT} from miden::protocol::auth

        #! Inputs: [PK_COMM, scheme_id]
        @account_procedure
        pub proc emit_auth_request
            # Prepend seven zero user params so the summary layout matches the auth procedure's.
            push.0.0.0.0.0.0.0
            exec.auth::create_tx_summary
            exec.auth::hash_and_insert_tx_summary
            # => [MESSAGE, PK_COMM, scheme_id]

            # With no pre-supplied signature the host must produce one, which is only allowed inside
            # the auth procedure; here it is not, so the transaction aborts.
            emit.AUTH_REQUEST_EVENT

            dropw dropw drop
        end
        ",
    )?;
    let probe_component = AccountComponent::new(
        probe_code,
        vec![],
        AccountComponentMetadata::new("mock::auth_request_probe"),
    )?;

    let mut builder = MockChain::builder();
    let account =
        builder.add_existing_account_from_components(Auth::IncrNonce, [probe_component.clone()])?;
    let chain = builder.build()?;

    // A dummy public key commitment; the request is rejected before any signature is verified.
    let pub_key_commitment = Word::from([1u32, 2, 3, 4]);
    let tx_script_source = format!(
        "
        @transaction_script
        pub proc main
            push.2
            push.{pub_key_commitment}
            # => [PK_COMM, scheme_id]

            call.::mock::auth_request_probe::emit_auth_request
        end
        "
    );

    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(probe_component.component_code())?
        .compile_tx_script(&tx_script_source)?;

    let execution_result = chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_matches!(
        execution_result,
        Err(TransactionExecutorError::AuthRequestOutsideAuthProcedure)
    );

    Ok(())
}

/// Complements [`test_auth_request_production_outside_auth_procedure_is_rejected`]: verifying an
/// externally supplied signature is always allowed, even outside the authentication procedure.
#[tokio::test]
async fn test_auth_request_verification_outside_auth_procedure_is_allowed() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let chain = builder.build()?;

    // A throwaway key signs an arbitrary message; the signature is placed in the advice map keyed
    // by `merge(pub_key_commitment, message)`, which is exactly where the host looks it up, so the
    // event resolves to the verification path rather than production.
    let message = Word::from([1u32, 2, 3, 4]);
    let secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let pub_key_commitment = secret_key.public_key().to_commitment();
    let authenticator = BasicAuthenticator::new(core::slice::from_ref(&secret_key));
    let signature = authenticator
        .get_signature(pub_key_commitment, &SigningInputs::Blind(message))
        .await?;

    // Mirror `auth::authenticate_transaction`'s signature request: [MESSAGE, PK_COMM, scheme_id].
    let tx_script_source = format!(
        "
        use {{AUTH_REQUEST_EVENT}} from miden::protocol::auth

        @transaction_script
        pub proc main
            push.2
            push.{pub_key_commitment}
            push.{message}
            # => [MESSAGE, PK_COMM, scheme_id]

            emit.AUTH_REQUEST_EVENT

            # drop the request inputs; the pushed signature stays on the advice stack, unused
            dropw dropw drop
        end
        "
    );

    let tx_script = CodeBuilder::new().compile_tx_script(&tx_script_source)?;

    // The request must be honored (no `AuthRequestOutsideAuthProcedure`), so the transaction runs
    // to completion under the trivial `IncrNonce` auth.
    chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .add_signature(pub_key_commitment, message, signature)
        .build()?
        .execute()
        .await
        .context("verifying an externally-supplied signature outside the auth procedure should be allowed")?;

    Ok(())
}

/// Regression test: an advice map entry under a signature key must not be able to make the host
/// allocate an encoded signature of an arbitrary length.
#[rstest]
#[case::empty(0)]
#[case::too_long(Signature::MAX_NUM_ENCODED_SIGNATURE_FELTS + 1)]
#[tokio::test]
async fn test_auth_request_with_invalid_encoded_signature_length_is_rejected(
    #[case] num_felts: usize,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::basic_falcon())?;
    let chain = builder.build()?;

    // Emit the request from a script with a precomputed message, but plant a malformed entry where
    // the host looks the signature up.
    let message = Word::from([1u32, 2, 3, 4]);
    let secret_key = AuthSecretKey::new_falcon512_poseidon2();
    let pub_key_commitment = secret_key.public_key().to_commitment();
    let signature_key = Hasher::merge(&[pub_key_commitment.into(), message]);
    let scheme_id = secret_key.auth_scheme().as_u8();

    let tx_script_source = format!(
        r#"
        use {{AUTH_REQUEST_EVENT}} from miden::protocol::auth

        @transaction_script
        pub proc main
            push.{scheme_id}
            push.{pub_key_commitment}
            push.{message}
            # => [MESSAGE, PK_COMM, scheme_id]

            emit.AUTH_REQUEST_EVENT

            push.0 assert.err="auth request handler should have aborted"
        end
        "#
    );

    let tx_script = CodeBuilder::new().compile_tx_script(&tx_script_source)?;

    let execution_result = chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .add_advice_map_entry(signature_key, vec![ZERO; num_felts])
        .build()?
        .execute()
        .await;

    assert_matches!(
        execution_result.unwrap_err(),
        TransactionExecutorError::TransactionProgramExecutionFailed(ExecutionError::EventError {
            error,
            ..
        }) => {
            assert_matches!(
                *error.downcast().unwrap(),
                TransactionKernelError::InvalidEncodedSignatureLength { actual, .. } => {
                    assert_eq!(actual, num_felts);
                }
            );
        }
    );

    Ok(())
}

/// Regression test: an untrusted script must not be able to forge the epilogue auth-procedure
/// boundary events that the host uses to gate signature production.
#[tokio::test]
async fn test_privileged_event_from_script_is_rejected() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let chain = builder.build()?;

    // A script executes in a non-root `dyncall` context, so it must not be able to emit the
    // kernel-only auth-procedure boundary event, reconstructed here from its event string.
    let tx_script_source = "
        const START_EVENT = event(\"miden::protocol::epilogue::auth_proc_start\")

        @transaction_script
        pub proc main
            emit.START_EVENT
        end
    ";

    let tx_script = CodeBuilder::new().compile_tx_script(tx_script_source)?;

    let execution_result = chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_matches!(
        execution_result,
        Err(TransactionExecutorError::PrivilegedEventFromOutsideTransactionKernelContext(_))
    );

    Ok(())
}
