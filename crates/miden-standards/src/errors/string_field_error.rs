use alloc::string::String;

/// Errors when encoding or decoding a fixed-width string metadata field.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StringFieldError {
    #[error("the field cannot contain a string over {0} characters long, but got {1}")]
    TooLong(usize, usize),
    #[error("The provided bytes are not a valid UTF-8 string: {0}")]
    InvalidUtf8(String),
}
