use crate::Word;

// WORD MOCK EXTENSION
// ================================================================================================

/// Extension trait to construct mock [`Word`]s for testing purposes.
pub trait WordMockExt {
    /// Returns a word whose four elements are all equal to `seed`.
    fn mock(seed: u32) -> Self;
}

impl WordMockExt for Word {
    fn mock(seed: u32) -> Self {
        Word::from([seed; 4])
    }
}
