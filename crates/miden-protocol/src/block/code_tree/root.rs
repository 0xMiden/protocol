use core::fmt::Display;

use miden_crypto_derive::WordWrapper;

use crate::Word;

// CODE TREE ROOT
// ================================================================================================

/// The root of the [`CodeTree`](super::CodeTree).
#[derive(Debug, Clone, Copy, PartialEq, Eq, WordWrapper)]
pub struct CodeTreeRoot(Word);

impl Display for CodeTreeRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_word())
    }
}

impl From<CodeTreeRoot> for Word {
    fn from(root: CodeTreeRoot) -> Self {
        root.as_word()
    }
}
