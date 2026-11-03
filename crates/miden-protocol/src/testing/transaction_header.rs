use alloc::vec::Vec;

use crate::Word;
use crate::block::code_tree::CodePatch;
use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use crate::transaction::{InputNotes, TransactionHeader};

impl TransactionHeader {
    /// Creates a transaction header without notes against a fixed private account, whose state
    /// commitments, and therefore its ID, are determined by `seed`.
    pub fn mock(seed: u32) -> Self {
        Self::new(
            ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
            Word::from([seed, 0, 0, 0]),
            Word::from([seed + 1, 0, 0, 0]),
            InputNotes::default(),
            Vec::new(),
            Word::empty(),
            CodePatch::default().commitment(),
        )
        .expect("mock transaction header should be valid")
    }
}
