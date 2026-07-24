extern crate alloc;

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_standards::account::inspection::CodeInspection;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

// HELPERS
// ================================================================================================

/// Builds an account exposing the `BasicWallet` and `CodeInspection` components.
fn create_inspectable_account() -> anyhow::Result<Account> {
    let account = AccountBuilder::new([1; 32])
        .account_type(AccountType::Public)
        .with_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_component(CodeInspection)
        .build_existing()?;

    Ok(account)
}

/// Runs a transaction against an account exposing `CodeInspection` whose tx script `call`s
/// `has_procedure` with `proc_root` (passed as the tx script argument) and runs `body` on the
/// returned availability flag. The transaction aborts if an assertion in `body` fails.
async fn run_has_procedure_script(proc_root: Word, body: &str) -> anyhow::Result<()> {
    let account = create_inspectable_account()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    // The tx script argument is placed on top of the initial operand stack, so the script starts
    // with `[PROC_ROOT, pad(12)]` - exactly the input `has_procedure` expects when invoked via
    // `call`. No `procref` is used so the stack depth stays at 16 across the call boundary.
    let tx_script_code = format!(
        r#"
        use miden::standards::components::inspection::code_inspection

        @transaction_script
        pub proc main
            # => [PROC_ROOT, pad(12)]
            call.code_inspection::has_procedure
            # => [is_procedure_available, pad(15)]
            {body}
        end
        "#
    );

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(CodeInspection::code())?
        .compile_tx_script(tx_script_code)?;

    mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .tx_script_args(proc_root)
        .build()?
        .execute()
        .await?;

    Ok(())
}

// TESTS
// ================================================================================================

/// `CodeInspection::has_procedure`, invoked via `call` from a transaction script, reports a
/// procedure that the account exposes as available (returns 1). A wrong result aborts the
/// transaction, so successful execution proves the flag was 1.
#[tokio::test]
async fn code_inspection_has_procedure_reports_exposed_procedure() -> anyhow::Result<()> {
    // `has_procedure` is itself exposed by the account, so its root must be reported as available.
    let exposed_root: Word = *CodeInspection::has_procedure_root().mast_root();

    run_has_procedure_script(
        exposed_root,
        r#"assert.err="has_procedure should report an exposed procedure as available""#,
    )
    .await?;

    Ok(())
}

/// `CodeInspection::has_procedure` reports a root that the account does not expose as unavailable
/// (returns 0).
#[tokio::test]
async fn code_inspection_has_procedure_reports_unknown_root() -> anyhow::Result<()> {
    // A root that is not a procedure of the account.
    let unknown_root = Word::from([5u32, 3, 15, 686]);

    run_has_procedure_script(
        unknown_root,
        r#"assertz.err="has_procedure should report an unknown root as unavailable""#,
    )
    .await?;

    Ok(())
}
