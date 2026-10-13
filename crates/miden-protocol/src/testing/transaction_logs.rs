use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use crate::transaction::{LogTopic, TransactionLog};
use crate::{Felt, Word};

impl LogTopic {
    /// Creates a topic from a suffix and prefix for testing.
    pub fn mock(suffix: u32, prefix: u32) -> Self {
        Self::new([Felt::from(suffix), Felt::from(prefix)])
    }
}

impl TransactionLog {
    /// Creates a log with a fixed private emitter and topic, repeating one content word.
    ///
    /// Panics if `num_words` exceeds [`Self::MAX_NUM_WORDS`].
    pub fn mock(num_words: usize) -> Self {
        Self::new(
            ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
            LogTopic::mock(1, 2),
            vec![Word::from([9u32, 10, 11, 12]); num_words],
        )
        .expect("mock log content must fit the per-log limit")
    }
}
