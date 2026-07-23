use anyhow::Context;
use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{Account, AccountBuilder};
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::ERR_EPILOGUE_AUTH_PROCEDURE_CALLED_FROM_WRONG_CONTEXT;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_protocol::{Felt, ONE, Word};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::{ConditionalAuthComponent, ERR_WRONG_ARGS_MSG};
use miden_standards::testing::mock_account::MockAccountExt;
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};

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
        Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, ConditionalAuthComponent);

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
        Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, ConditionalAuthComponent);

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
    let (auth_component, _) = Auth::IncrNonce.build_component();

    let account = AccountBuilder::new([42; 32])
        .with_auth_component(auth_component.clone())
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

/// Regression test: an untrusted transaction script must not be able to force the host to produce a
/// signature.
///
/// The script emits `AUTH_REQUEST` directly, supplying a precomputed message on the stack and a
/// matching signature in the advice map. This deliberately bypasses `auth::create_tx_summary`
/// (which computes `account::compute_delta_commitment` and is now gated to the account context, so
/// it cannot be called from a script) and exercises the host's context check in isolation: the
/// request must be rejected with `AuthRequestOutsideAuthProcedure` because it originates outside
/// the authentication procedure. The check runs before the signature is validated, so a throwaway
/// key is sufficient - the test is intentionally artificial and only asserts that the original
/// error path is still reachable.
#[tokio::test]
async fn test_auth_request_from_script_is_rejected() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let chain = builder.build()?;

    // Precompute the AUTH_REQUEST inputs instead of building the summary on-chain. A throwaway key
    // signs an arbitrary message; the resulting signature is placed in the advice map keyed by
    // `merge(pub_key_commitment, message)`, which is exactly where the host looks it up.
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

            # unreachable once the request is rejected; keeps the script well-formed
            dropw dropw drop
        end
        "
    );

    let tx_script = CodeBuilder::new().compile_tx_script(&tx_script_source)?;

    let execution_result = chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .add_signature(pub_key_commitment, message, signature)
        .build()?
        .execute()
        .await;

    assert_matches!(
        execution_result,
        Err(TransactionExecutorError::AuthRequestOutsideAuthProcedure)
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
