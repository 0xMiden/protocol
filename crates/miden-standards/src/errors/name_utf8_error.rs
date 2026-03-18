//! Error type for metadata name UTF-8 encoding/decoding.

use thiserror::Error;

/// Errors when encoding or decoding the metadata name as UTF-8.
#[derive(Debug, Clone, Error)]
pub enum NameUtf8Error {
    /// Name exceeds the maximum of 32 UTF-8 bytes.
    #[error("name must be at most 32 UTF-8 bytes, got {0}")]
    TooLong(usize),
    /// Decoded bytes are not valid UTF-8.
    #[error("name is not valid UTF-8")]
    InvalidUtf8,
}
