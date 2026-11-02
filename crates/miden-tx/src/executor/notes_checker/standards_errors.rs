//! Private copies of the `miden::standards` errors the note checker uses to recognize why an
//! execution failed.
//!
//! The generated constants in `miden_standards::errors::standards` are only available with the
//! `testing` feature, so they are not part of that crate's stable API. The tests below pin each
//! copy against its generated constant.

use miden_protocol::errors::MasmError;

/// Error Message: "FEE_SPONSORSHIP note asset does not match the fee asset the account accepts"
pub(super) const ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET: MasmError = MasmError::from_static_str(
    "FEE_SPONSORSHIP note asset does not match the fee asset the account accepts",
);

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_standards::errors::standards;

    use super::*;

    #[test]
    fn copies_match_generated_errors() {
        assert_eq!(
            ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET.message(),
            standards::ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET.message()
        );
    }
}
