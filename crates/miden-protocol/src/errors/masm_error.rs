use alloc::borrow::Cow;

use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;

use crate::Felt;

/// A convenience wrapper around an error extracted from Miden Assembly source files.
pub struct MasmError {
    message: Cow<'static, str>,
}

impl MasmError {
    /// Constructs a new error from a static str.
    pub const fn from_static_str(message: &'static str) -> Self {
        Self { message: Cow::Borrowed(message) }
    }

    /// Constructs a new error from string.
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        let message = message.into();

        Self { message }
    }

    /// Returns the message of this error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the code of this error.
    pub fn code(&self) -> Felt {
        crate::assembly::mast::error_code_from_msg(&self.message)
    }

    /// Returns `true` if `error` is an `OperationError::FailedAssertion` whose `err_code` equals
    /// this error's [code](Self::code).
    ///
    /// If the actual error carries an `err_msg`, it must also equal this error's
    /// [message](Self::message); an absent `err_msg` is accepted.
    pub fn matches_execution_error(&self, error: &ExecutionError) -> bool {
        let ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg },
            ..
        } = error
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

impl core::fmt::Display for MasmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("\"{}\" (code: {})", self.message(), self.code()))
    }
}
