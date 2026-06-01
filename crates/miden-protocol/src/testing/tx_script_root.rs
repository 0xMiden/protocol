use crate::Word;
use crate::transaction::TransactionScriptRoot;

impl TransactionScriptRoot {
    /// Creates a [`TransactionScriptRoot`] from an array of u32s for testing purposes.
    pub fn from_array(array: [u32; 4]) -> Self {
        Self::from_raw(Word::from(array))
    }
}
