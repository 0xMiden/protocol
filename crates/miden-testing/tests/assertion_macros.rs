//! Tests for `assert_execution_error!` and `assert_transaction_executor_error!`.
//!
//! - Sync tests build errors directly to exercise the macro grammar
//!   (each arm + `#[should_panic]` for failure paths).
//! - Async tests run small MASM programs on `FastProcessor` to cover real
//!   `ExecutionError` variants end-to-end.

extern crate alloc;

use alloc::format;
use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager, SourceSpan};
use miden_core_lib::CoreLibrary;
use miden_processor::advice::AdviceError;
use miden_processor::operation::OperationError;
use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOptions,
    ExecutionOutput,
    FastProcessor,
    Felt,
    MemoryError,
    StackInputs,
};
use miden_testing::{ExecError, assert_execution_error, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;

// HELPERS
// ================================================================================================

fn op_error(err: OperationError) -> ExecutionError {
    ExecutionError::OperationError {
        label: SourceSpan::default(),
        source_file: None,
        err,
    }
}

fn failed_assertion(err_code: u64) -> ExecutionError {
    op_error(OperationError::FailedAssertion {
        err_code: Felt::new(err_code),
        err_msg: None,
    })
}

fn exec_err(err: ExecutionError) -> Result<(), ExecError> {
    Err(ExecError::new(err))
}

fn tx_err(err: ExecutionError) -> Result<(), TransactionExecutorError> {
    Err(TransactionExecutorError::TransactionProgramExecutionFailed(err))
}

/// Assembles `src` and runs it on a default `FastProcessor` with no advice
/// inputs and an empty stack. Returned errors are wrapped in [`ExecError`].
async fn run_masm(src: &str) -> Result<ExecutionOutput, ExecError> {
    run_masm_with_options(src, ExecutionOptions::default()).await
}

/// Same as [`run_masm`] but allows overriding [`ExecutionOptions`].
async fn run_masm_with_options(
    src: &str,
    options: ExecutionOptions,
) -> Result<ExecutionOutput, ExecError> {
    let core_lib = CoreLibrary::default();
    let assembler = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(&core_lib)
        .expect("CoreLibrary should load");
    let program = assembler.assemble_program(src).expect("MASM should assemble");

    let mut host = DefaultHost::default();
    host.load_library(core_lib.mast_forest())
        .expect("CoreLibrary mast forest should load");

    let stack = StackInputs::new(&[]).expect("empty stack inputs are valid");
    FastProcessor::new(stack)
        .with_options(options)
        .execute(&program, &mut host)
        .await
        .map_err(ExecError::new)
}

// EXECUTION-ERROR ASSERTION TESTS — direct construction
// ================================================================================================

// `matches` arm — outer ExecutionError variants
#[test]
fn assert_execution_error_matches_outer_variant() {
    let r = exec_err(ExecutionError::CycleLimitExceeded(42));
    assert_execution_error!(r, matches ExecutionError::CycleLimitExceeded(_));

    let r = exec_err(ExecutionError::OutputStackOverflow(7));
    assert_execution_error!(r, matches ExecutionError::OutputStackOverflow(_));
}

// `matches` arm — inner OperationError variants
#[test]
fn assert_execution_error_matches_inner_operation_variant() {
    let r = exec_err(op_error(OperationError::DivideByZero));
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError { err: OperationError::DivideByZero, .. }
    );

    let r = exec_err(op_error(OperationError::LogArgumentZero));
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError { err: OperationError::LogArgumentZero, .. }
    );
}

// `matches` arm — pattern guard on FailedAssertion err_code
#[test]
fn assert_execution_error_matches_with_guard() {
    let r = exec_err(failed_assertion(0x1234));
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } if err_code == Felt::new(0x1234)
    );
}

// `any` arm — succeeds on any Err
#[test]
fn assert_execution_error_any_accepts_any_error() {
    let r = exec_err(ExecutionError::OutputStackOverflow(7));
    assert_execution_error!(r, any);

    let r = exec_err(op_error(OperationError::DivideByZero));
    assert_execution_error!(r, any);
}

#[test]
#[should_panic(expected = "Execution was unexpectedly successful")]
fn assert_execution_error_matches_panics_on_ok() {
    let r: Result<(), ExecError> = Ok(());
    assert_execution_error!(r, matches ExecutionError::CycleLimitExceeded(_));
}

#[test]
#[should_panic(expected = "did not match")]
fn assert_execution_error_matches_panics_on_pattern_mismatch() {
    let r = exec_err(ExecutionError::CycleLimitExceeded(1));
    assert_execution_error!(r, matches ExecutionError::OutputStackOverflow(_));
}

#[test]
#[should_panic(expected = "did not match")]
fn assert_execution_error_matches_panics_on_guard_mismatch() {
    let r = exec_err(failed_assertion(0x1234));
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } if err_code == Felt::new(0xdead)
    );
}

#[test]
#[should_panic(expected = "Execution was unexpectedly successful")]
fn assert_execution_error_any_panics_on_ok() {
    let r: Result<(), ExecError> = Ok(());
    assert_execution_error!(r, any);
}

// TRANSACTION-EXECUTOR-ERROR ASSERTION TESTS — direct construction
// ================================================================================================

#[test]
fn assert_transaction_executor_error_matches_outer_variant() {
    let r = tx_err(ExecutionError::CycleLimitExceeded(42));
    assert_transaction_executor_error!(r, matches ExecutionError::CycleLimitExceeded(_));
}

#[test]
fn assert_transaction_executor_error_matches_inner_operation_variant() {
    let r = tx_err(op_error(OperationError::DivideByZero));
    assert_transaction_executor_error!(
        r,
        matches ExecutionError::OperationError { err: OperationError::DivideByZero, .. }
    );
}

#[test]
fn assert_transaction_executor_error_matches_with_guard() {
    let r = tx_err(failed_assertion(0xabcd));
    assert_transaction_executor_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } if err_code == Felt::new(0xabcd)
    );
}

#[test]
fn assert_transaction_executor_error_any_accepts_any_error() {
    let r = tx_err(ExecutionError::OutputStackOverflow(7));
    assert_transaction_executor_error!(r, any);
}

#[test]
#[should_panic(expected = "did not match")]
fn assert_transaction_executor_error_matches_panics_on_pattern_mismatch() {
    let r = tx_err(ExecutionError::CycleLimitExceeded(1));
    assert_transaction_executor_error!(r, matches ExecutionError::OutputStackOverflow(_));
}

#[test]
#[should_panic(expected = "Execution was unexpectedly successful")]
fn assert_transaction_executor_error_any_panics_on_ok() {
    let r: Result<(), TransactionExecutorError> = Ok(());
    assert_transaction_executor_error!(r, any);
}

// VM-DRIVEN VARIANT COVERAGE
// ================================================================================================

#[tokio::test]
async fn divide_by_zero() {
    // 5 / 0 — top of stack is the divisor.
    let r = run_masm("begin push.5 push.0 div end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::DivideByZero,
            ..
        }
    );
}

#[tokio::test]
async fn log_argument_zero() {
    let r = run_masm("begin push.0 ilog2 end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::LogArgumentZero,
            ..
        }
    );
}

#[tokio::test]
async fn not_binary_value() {
    let r = run_masm("begin push.2 push.1 and end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::NotBinaryValue { .. },
            ..
        }
    );
}

#[tokio::test]
async fn not_binary_value_if() {
    let r = run_masm("begin push.2 if.true push.0 drop else push.0 drop end end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::NotBinaryValueIf { .. },
            ..
        }
    );
}

#[tokio::test]
async fn not_binary_value_loop() {
    let r = run_masm("begin push.2 while.true push.0 end end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::NotBinaryValueLoop { .. },
            ..
        }
    );
}

#[tokio::test]
async fn not_u32_values() {
    let r = run_masm("begin push.4294967296 u32assert end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::NotU32Values { .. },
            ..
        }
    );
}

#[tokio::test]
async fn vm_failed_assertion() {
    let r = run_masm(r#"begin push.0 assert.err="custom failure" end"#).await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::FailedAssertion { .. },
            ..
        }
    );
}

#[tokio::test]
async fn output_stack_overflow() {
    // Default stack starts at depth 16; push 5 extras → 21 at end.
    let r = run_masm("begin push.1 push.1 push.1 push.1 push.1 end").await;
    assert_execution_error!(r, matches ExecutionError::OutputStackOverflow(_));
}

#[tokio::test]
async fn cycle_limit_exceeded() {
    // Set max_cycles to MIN_TRACE_LEN (64); 100×push body trips it.
    let body = "push.0 ".repeat(100);
    let src = format!("begin {body} end");
    let options = ExecutionOptions::new(Some(64), 64, 4096, false, false)
        .expect("max_cycles=64 satisfies MIN_TRACE_LEN");
    let r = run_masm_with_options(&src, options).await;
    assert_execution_error!(r, matches ExecutionError::CycleLimitExceeded(_));
}

#[tokio::test]
async fn memory_unaligned_word_access() {
    let r = run_masm("begin push.1 mem_loadw_be end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::MemoryError {
            err: MemoryError::UnalignedWordAccess { .. },
            ..
        }
    );
}

#[tokio::test]
async fn advice_error_empty_stack() {
    let r = run_masm("begin adv_push.1 end").await;
    assert_execution_error!(
        r,
        matches ExecutionError::AdviceError {
            err: AdviceError::StackReadFailed,
            ..
        }
    );
}

#[tokio::test]
async fn invalid_stack_depth_on_return() {
    let src = "
        proc bad
            push.1 push.2 push.3
        end
        begin
            call.bad
        end
    ";
    let r = run_masm(src).await;
    assert_execution_error!(
        r,
        matches ExecutionError::OperationError {
            err: OperationError::InvalidStackDepthOnReturn { .. },
            ..
        }
    );
}

#[tokio::test]
async fn event_error_unregistered() {
    let src = r#"
        const MY_EVENT=event("miden::testing::asserts::unregistered")
        begin
            emit.MY_EVENT
        end
    "#;
    let r = run_masm(src).await;
    assert_execution_error!(r, matches ExecutionError::EventError { .. });
}

#[tokio::test]
async fn procedure_not_found_via_dynexec() {
    // `dynexec` looks up the digest popped from the stack in the host's MAST
    // forest; a digest of zeros is not a real procedure root.
    let r = run_masm("begin push.0.0.0.0 dynexec end").await;
    assert_execution_error!(r, matches ExecutionError::ProcedureNotFound { .. });
}
