//! Matcher trait used by the `$expected` arm of `assert_execution_error!`
//! and `assert_transaction_executor_error!`. The built-in impl for
//! [`MasmError`] preserves the legacy behavior (compare against
//! `OperationError::FailedAssertion`).

use core::fmt::Display;

use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;
use miden_protocol::errors::MasmError;

/// Matcher for an expected [`ExecutionError`] shape.
/// `Display` is required so the macro can format a panic message on mismatch.
pub trait ExpectedExecutionError: Display {
    fn matches(&self, actual: &ExecutionError) -> bool;
}

/// Matches `FailedAssertion` with the same `err_code`. If the actual error
/// carries an `err_msg`, it must equal the constant's message; an absent
/// `err_msg` is accepted.
impl ExpectedExecutionError for MasmError {
    fn matches(&self, actual: &ExecutionError) -> bool {
        let ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg },
            ..
        } = actual
        else {
            return false;
        };

        if *err_code != self.code() {
            return false;
        }

        match err_msg {
            Some(msg) => msg.as_ref() == self.message(),
            None => true,
        }
    }
}
