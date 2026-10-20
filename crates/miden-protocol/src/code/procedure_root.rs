use core::fmt::Display;

use miden_crypto_derive::WordWrapper;

use crate::Word;

// PROCEDURE ROOT
// ================================================================================================

/// The MAST root of a procedure, such as an account procedure, a note script root or an external
/// node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, WordWrapper)]
pub struct ProcedureRoot(Word);

impl Display for ProcedureRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_word())
    }
}

impl From<ProcedureRoot> for Word {
    fn from(root: ProcedureRoot) -> Self {
        root.as_word()
    }
}
