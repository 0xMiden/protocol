use miden_core::utils::hash_string_to_word;

use crate::Felt;

/// An opaque two felt transaction log topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogTopic {
    suffix: Felt,
    prefix: Felt,
}

impl LogTopic {
    /// Creates a topic from its suffix and prefix.
    pub const fn new(suffix: Felt, prefix: Felt) -> Self {
        Self { suffix, prefix }
    }

    /// Derives a topic from the first two elements of a MASM `word(name)` constant.
    pub fn from_name(name: &str) -> Self {
        let word = hash_string_to_word(name);
        Self::new(word[0], word[1])
    }

    /// Returns the topic's suffix.
    pub const fn suffix(&self) -> Felt {
        self.suffix
    }

    /// Returns the topic's prefix.
    pub const fn prefix(&self) -> Felt {
        self.prefix
    }
}
