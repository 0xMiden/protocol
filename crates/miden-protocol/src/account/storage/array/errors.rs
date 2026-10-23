/// Errors when constructing or updating a storage array.
#[derive(Debug, thiserror::Error)]
pub enum StorageArrayError {
    #[error("storage array length must be between 1 and {max} words, got {0}", max = super::StorageArray::MAX_NUM_WORDS)]
    InvalidLength(usize),
    #[error("storage array index {index} is outside array length {length}")]
    IndexOutOfBounds { index: u16, length: u16 },
    #[error("storage array patch contains duplicate index {0}")]
    DuplicateIndex(u16),
    #[error("storage array length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: u16, actual: u16 },
}
