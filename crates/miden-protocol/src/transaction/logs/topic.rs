use miden_core::utils::hash_string_to_word;

use crate::Felt;

/// An opaque two felt transaction log topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogTopic {
    suffix: Felt,
    prefix: Felt,
}

impl LogTopic {
    /// Creates a topic from its field elements, in metadata order.
    pub const fn new([suffix, prefix]: [Felt; 2]) -> Self {
        Self { suffix, prefix }
    }

    /// Derives a topic from the first two elements of a MASM `word(name)` constant.
    pub fn from_name(name: &str) -> Self {
        let word = hash_string_to_word(name);
        Self::new([word[0], word[1]])
    }

    /// Returns the topic's elements in metadata order.
    pub const fn as_elements(&self) -> [Felt; 2] {
        [self.suffix, self.prefix]
    }
}
