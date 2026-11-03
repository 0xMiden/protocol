use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use crate::transaction::{LogTopic, TransactionLog};
use crate::{Felt, Word};

impl LogTopic {
    /// Creates a topic from a suffix and prefix for testing.
    pub fn mock(suffix: u32, prefix: u32) -> Self {
        Self::new(Felt::from(suffix), Felt::from(prefix))
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

impl crate::transaction::PublicTransactionLogs {
    /// Creates empty public collections for grouped block fixture headers.
    pub fn mock_for_block(headers: &[crate::transaction::OrderedTransactionHeaders]) -> Self {
        Self::mock(&crate::transaction::OrderedTransactionHeaders::new_unchecked(
            headers.iter().flat_map(|batch| batch.as_slice()).cloned().collect(),
        ))
    }

    /// Creates empty public collections for fixture headers whose public log commitments are empty.
    ///
    /// Duplicate fixture headers share one entry so owner-validation tests can reject them.
    /// Panics if a public header commits to nonempty logs.
    pub fn mock(headers: &crate::transaction::OrderedTransactionHeaders) -> Self {
        let mut ids = alloc::collections::BTreeSet::new();
        let headers = crate::transaction::OrderedTransactionHeaders::new_unchecked(
            headers
                .as_slice()
                .iter()
                .filter(|header| ids.insert(header.id()))
                .cloned()
                .collect(),
        );
        Self::new(
            headers
                .as_slice()
                .iter()
                .filter(|header| header.account_id().is_public())
                .map(|header| (header.id(), crate::transaction::TransactionLogs::default()))
                .collect(),
            &headers,
        )
        .expect("fixture headers should have empty public log commitments and unique IDs")
    }
}
