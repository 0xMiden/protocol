use alloc::borrow::Cow;

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
}

impl core::fmt::Display for MasmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("\"{}\" (code: {})", self.message(), self.code()))
    }
}
