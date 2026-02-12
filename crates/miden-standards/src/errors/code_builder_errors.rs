use alloc::boxed::Box;
use alloc::string::String;
use core::error::Error;

use miden_protocol::assembly::diagnostics::Report;
use miden_protocol::assembly::diagnostics::reporting::PrintDiagnostic;

// CODE BUILDER ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
#[error("failed to build script: {message}")]
pub struct CodeBuilderError {
    /// Stack size of `Box<str>` is smaller than String.
    message: Box<str>,
    /// thiserror will return this when calling Error::source on CodeBuilderError.
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl CodeBuilderError {
    /// Creates a code builder error from an error message and a source error.
    pub fn build_error_with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message: String = message.into();
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Creates a code builder error from a context message and a Report.
    ///
    /// This method uses PrintDiagnostic to stringify the Report since Report doesn't
    /// implement core::error::Error and cannot be returned as a source error.
    pub fn build_error_with_report(context: impl Into<String>, report: Report) -> Self {
        let context: String = context.into();
        let message = format!("{}: {}", context, PrintDiagnostic::new(&report));
        Self { message: message.into(), source: None }
    }
}

#[cfg(test)]
mod error_assertions {
    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_code_builder_error_bounds(err: CodeBuilderError) {
        _assert_error_is_send_sync_static(err);
    }
}
