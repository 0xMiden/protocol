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

/// Tests that attempting to call the auth procedure manually from user code fails.
#[tokio::test]
async fn test_auth_procedure_called_from_wrong_context() -> anyhow::Result<()> {
    let (auth_components, _) = Auth::IncrNonce.build_components();
    let auth_component = auth_components.into_iter().next().expect("auth component is yielded");

    let account = AccountBuilder::new([42; 32])
        .with_component(auth_component.clone())
        .with_component(BasicWallet)
        .build_existing()?;

    // Create a transaction script that calls the auth procedure
    let tx_script_source = "
        @transaction_script
        pub proc main
            call.::incr_nonce::auth_incr_nonce
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

/// Regression test for the epilogue's "auth procedure must not be called by user code" guard when
/// the auth procedure does not increment the nonce.
///
/// The guard (`epilogue.masm`) relies on the auth procedure's own kernel calls being tracked: if a
/// note or transaction script invokes the auth procedure during the main phase, the calls it makes
/// set `was_called[0]`, and the epilogue aborts. Call-tracking is suppressed only while the
/// epilogue-auth-in-progress flag is set, so a main-phase invocation (flag unset) is still
/// tracked.
///
/// This uses an auth procedure that makes a gated kernel call (`get_initial_commitment`) but never
/// increments the nonce - the case that a caller-index-based exemption would miss, since the only
/// other writer of `was_called[0]` is the nonce increment.
#[tokio::test]
async fn test_non_incrementing_auth_procedure_called_from_wrong_context() -> anyhow::Result<()> {
    // An auth component whose auth procedure makes a gated kernel call but never increments the
    // nonce.
    let auth_src = "
        use miden::protocol::native_account

        @auth_script
        pub proc auth_read_only
            # a gated kernel call; invoked from user code during the main phase (epilogue-auth-in-
            # progress flag unset) it records was_called[0], which the epilogue's replay guard rejects
            exec.native_account::get_initial_commitment dropw
            # deliberately never increment the nonce
            dropw dropw dropw dropw
        end
    ";
    let auth_code =
        CodeBuilder::default().compile_component_code("mock::read_only_auth", auth_src)?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("mock::read_only_auth"),
    )?;

    let account = AccountBuilder::new([42; 32])
        .with_component(auth_component.clone())
        .with_component(BasicWallet)
        .build_existing()?;

    // A transaction script that invokes the account's auth procedure during the main phase.
    let tx_script_source = "
        @transaction_script
        pub proc main
            call.::mock::read_only_auth::auth_read_only
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

/// Future-proofing regression: a procedure invoked via `call` from the auth procedure must not be
/// tracked, even though its own kernel calls are attributed to it (not to the auth procedure).
///
/// Tracking is suppressed for the whole epilogue auth run via the epilogue-auth-in-progress flag,
/// so this holds regardless of how the auth procedure reaches the kernel. A
/// caller-index-based exemption (skipping only index 0) would instead track the invoked procedure.
/// The auth procedure asserts the non-tracking itself, so a regression makes the transaction fail.
#[tokio::test]
async fn test_procedure_called_from_auth_procedure_is_not_tracked() -> anyhow::Result<()> {
    let component_src = "
        use miden::protocol::native_account

        @account_procedure
        pub proc touch_state
            # a gated kernel call; invoked via `call` from the auth procedure so that the call is
            # attributed to `touch_state` (index != 0)
            exec.native_account::get_initial_commitment dropw
        end

        @auth_script
        pub proc auth_check_tracking
            # invoke the helper via `call`
            call.touch_state

            # the helper must NOT be recorded as called, because tracking is suppressed while the
            # auth procedure runs
            procref.touch_state
            exec.native_account::was_procedure_called
            assertz.err=\"procedure called from the auth procedure must not be tracked\"

            # increment the nonce so the transaction changes state and is valid
            exec.native_account::incr_nonce drop

            # clean up the auth args frame
            dropw dropw dropw dropw
        end
    ";
    let component_code =
        CodeBuilder::default().compile_component_code("mock::flag_tracking_auth", component_src)?;
    let component = AccountComponent::new(
        component_code,
        vec![],
        AccountComponentMetadata::mock("mock::flag_tracking_auth"),
    )?;

    let account = AccountBuilder::new([7; 32])
        .with_component(component)
        .with_component(BasicWallet)
        .build_existing()?;

    let mock_tx = TestTransactionBuilder::new(account).build()?;

    // If the helper were tracked, the auth procedure's `assertz` would fail and execution would
    // err.
    mock_tx.execute().await.context("auth-procedure call-tracking regression")?;

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
