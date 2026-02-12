use anyhow::Context;
use miden_protocol::account::{Account, AccountBuilder};
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::ERR_EPILOGUE_AUTH_PROCEDURE_CALLED_FROM_WRONG_CONTEXT;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_protocol::{Felt, ONE};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::{ConditionalAuthComponent, ERR_WRONG_ARGS_MSG};
use miden_standards::testing::mock_account::MockAccountExt;

use crate::{Auth, TransactionContextBuilder, assert_transaction_executor_error};

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
        ONE, // incr_nonce = true
        Felt::new(99),
        Felt::new(98),
        Felt::new(97),
    ];

    let tx_context = TransactionContextBuilder::new(account).auth_args(auth_args.into()).build()?;

    tx_context.execute().await.context("failed to execute transaction")?;

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
        Felt::new(103),
        Felt::new(102),
        Felt::new(101),
    ];

    let tx_context = TransactionContextBuilder::new(account).auth_args(auth_args.into()).build()?;

    let execution_result = tx_context.execute().await;

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
        begin
            call.::incr_nonce::auth_incr_nonce
        end
    ";

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(auth_component.component_code())?
        .compile_tx_script(tx_script_source)?;

    let tx_context = TransactionContextBuilder::new(account).tx_script(tx_script).build()?;

    let execution_result = tx_context.execute().await;

    assert_transaction_executor_error!(
        execution_result,
        ERR_EPILOGUE_AUTH_PROCEDURE_CALLED_FROM_WRONG_CONTEXT
    );

    Ok(())
}
