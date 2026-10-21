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
        .with_components(Auth::IncrNonce)
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

    run_inspection_script(&account, tx_script_code, proc_root).await
}

/// Runs the given tx script, compiled against the `CodeInspection` component, against `account`
/// with `script_arg` as the tx script argument. The transaction aborts if an assertion in the
/// script fails.
async fn run_inspection_script(
    account: &Account,
    tx_script_code: String,
    script_arg: Word,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(CodeInspection::code())?
        .compile_tx_script(tx_script_code)?;

    mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .tx_script_args(script_arg)
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

/// `CodeInspection::get_code_commitment`, invoked via `call` from a transaction script, returns the
/// commitment to the account's code and honours the 16-felt call ABI.
#[tokio::test]
async fn code_inspection_get_code_commitment() -> anyhow::Result<()> {
    let account = create_inspectable_account()?;
    let expected_code_commitment = account.code().commitment();

    // The getter expects `[pad(16)]`, so the script pads the stack before the call. The padding
    // sits above the tx script argument, which the call leaves untouched.
    let tx_script_code = format!(
        r#"
        use miden::standards::components::inspection::code_inspection

        @transaction_script
        pub proc main
            padw padw padw padw
            call.code_inspection::get_code_commitment
            # => [CODE_COMMITMENT, pad(12), pad(16)]
            push.{expected_code_commitment}
            assert_eqw.err="get_code_commitment returned an unexpected commitment or violated the call ABI"
            dropw dropw dropw
        end
        "#
    );

    run_inspection_script(&account, tx_script_code, Word::empty()).await?;

    Ok(())
}

/// `CodeInspection::get_num_procedures`, invoked via `call` from a transaction script, returns the
/// number of procedures the account exposes and honours the 16-felt call ABI.
#[tokio::test]
async fn code_inspection_get_num_procedures() -> anyhow::Result<()> {
    let account = create_inspectable_account()?;
    let expected_num_procedures = account.code().procedures().len();

    let tx_script_code = format!(
        r#"
        use miden::standards::components::inspection::code_inspection

        @transaction_script
        pub proc main
            padw padw padw padw
            call.code_inspection::get_num_procedures
            # => [num_procedures, pad(15), pad(16)]
            push.{expected_num_procedures}
            assert_eq.err="get_num_procedures returned an unexpected count or violated the call ABI"
            dropw dropw dropw drop drop drop
        end
        "#
    );

    run_inspection_script(&account, tx_script_code, Word::empty()).await?;

    Ok(())
}

/// `CodeInspection::get_procedure_root`, invoked via `call` from a transaction script, returns the
/// root of the procedure at the requested index and honours the 16-felt call ABI.
#[tokio::test]
async fn code_inspection_get_procedure_root() -> anyhow::Result<()> {
    let account = create_inspectable_account()?;
    let expected_proc_root = account.code().procedures()[0].as_word();

    // The getter expects `[index, pad(15)]`, so the script pads 15 elements before the index.
    let tx_script_code = format!(
        r#"
        use miden::standards::components::inspection::code_inspection

        @transaction_script
        pub proc main
            padw padw padw push.0.0.0
            push.0
            call.code_inspection::get_procedure_root
            # => [PROC_ROOT, pad(12), pad(16)]
            push.{expected_proc_root}
            assert_eqw.err="get_procedure_root returned an unexpected root or violated the call ABI"
            dropw dropw dropw
        end
        "#
    );

    run_inspection_script(&account, tx_script_code, Word::empty()).await?;

    Ok(())
}
