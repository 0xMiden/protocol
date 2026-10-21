use alloc::string::ToString;

use miden_processor::ExecutionError;
use miden_protocol::assembly::diagnostics::reporting::PrintDiagnostic;
use thiserror::Error;

// EXECUTION ERROR
// ================================================================================================

/// A newtype wrapper around [`ExecutionError`] that provides better error messages
/// by using [`PrintDiagnostic`] for display formatting.
#[derive(Debug, Error)]
#[error("{}", PrintDiagnostic::new(.0).to_string())]
pub struct ExecError(pub ExecutionError);

impl ExecError {
    /// Creates a new `ExecError` from an `ExecutionError`.
    pub fn new(error: ExecutionError) -> Self {
        Self(error)
    }

    /// Returns a reference to the inner `ExecutionError`.
    pub fn as_execution_error(&self) -> &ExecutionError {
        &self.0
    }

    /// Consumes `ExecError` and returns the inner `ExecutionError`.
    pub fn into_execution_error(self) -> ExecutionError {
        self.0
    }
}
