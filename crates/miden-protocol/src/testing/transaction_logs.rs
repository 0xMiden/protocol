use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use crate::transaction::{
    LogTopic,
    OrderedTransactionHeaders,
    PublicTransactionLogs,
    TransactionHeader,
    TransactionLog,
    TransactionLogs,
};
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

impl PublicTransactionLogs {
    /// Builds matching headers and nonempty public logs from fixture header templates.
    ///
    /// Replaces public log commitments and recomputes transaction IDs, preserving all other
    /// fields. Private headers remain unchanged. Callers must use the returned headers.
    ///
    /// # Panics
    /// Panics if the templates contain invalid note associations or exceed the public-content-word
    /// limit.
    pub fn mock(headers: OrderedTransactionHeaders) -> (OrderedTransactionHeaders, Self) {
        let (mut batches, logs) = Self::mock_for_block(vec![headers]);
        (batches.remove(0), logs)
    }

    /// Builds matching grouped headers and nonempty public logs from fixture header templates.
    ///
    /// Preserves batch grouping, order, and duplicate headers. Duplicate headers share one log
    /// entry so checked owner constructors can reject deliberately invalid fixtures. Private
    /// headers remain unchanged and have no public log entry.
    ///
    /// # Panics
    /// Panics if the templates contain invalid note associations or exceed the public-content-word
    /// limit.
    pub fn mock_for_block(
        batches: Vec<OrderedTransactionHeaders>,
    ) -> (Vec<OrderedTransactionHeaders>, Self) {
        let mock_logs = TransactionLogs::new(vec![TransactionLog::mock(1)])
            .expect("mock logs should fit the transaction limits");
        let batches: Vec<_> = batches
            .into_iter()
            .map(|batch| {
                OrderedTransactionHeaders::new_unchecked(
                    batch
                        .into_vec()
                        .into_iter()
                        .map(|header| {
                            if !header.account_id().is_public() {
                                return header;
                            }
                            TransactionHeader::new(
                                header.account_id(),
                                header.initial_state_commitment(),
                                header.final_state_commitment(),
                                header.input_notes().clone(),
                                header.output_notes().to_vec(),
                                mock_logs.commitment(),
                                header.code_patch_commitment(),
                            )
                            .expect("fixture headers should have valid note associations")
                        })
                        .collect(),
                )
            })
            .collect();
        let mut ids = BTreeSet::new();
        let unique: Vec<_> = batches
            .iter()
            .flat_map(OrderedTransactionHeaders::as_slice)
            .filter(|header| ids.insert(header.id()))
            .collect();
        let entries = unique
            .iter()
            .filter(|header| header.account_id().is_public())
            .map(|header| (header.id(), mock_logs.clone()))
            .collect();
        let logs = Self::new(entries, unique.into_iter())
            .expect("fixture public logs should match their rebuilt headers and fit the limit");
        (batches, logs)
    }
}

#[cfg(test)]
mod tests {
    use crate::Word;
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use crate::transaction::{OrderedTransactionHeaders, PublicTransactionLogs, TransactionHeader};

    fn public_header(seed: u32) -> TransactionHeader {
        let template = TransactionHeader::mock(seed);
        TransactionHeader::new(
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE.try_into().unwrap(),
            template.initial_state_commitment(),
            template.final_state_commitment(),
            template.input_notes().clone(),
            template.output_notes().to_vec(),
            Word::empty(),
            template.code_patch_commitment(),
        )
        .unwrap()
    }

    #[test]
    fn mock_public_logs_include_content() {
        let public = public_header(1);
        let headers = OrderedTransactionHeaders::new_unchecked(vec![public.clone()]);
        let (headers, logs) = PublicTransactionLogs::mock(headers);
        logs.validate(headers.as_slice().iter()).unwrap();
        assert!(!logs.entries()[0].1.is_empty());
        let rebuilt = &headers.as_slice()[0];
        assert_ne!(rebuilt.id(), public.id());
        assert_eq!(rebuilt.logs_commitment(), logs.entries()[0].1.commitment());
        assert_eq!(logs.entries()[0].0, rebuilt.id());
        assert_eq!(rebuilt.account_id(), public.account_id());
        assert_eq!(rebuilt.initial_state_commitment(), public.initial_state_commitment());
        assert_eq!(rebuilt.final_state_commitment(), public.final_state_commitment());
        assert_eq!(rebuilt.input_notes(), public.input_notes());
        assert_eq!(rebuilt.output_notes(), public.output_notes());
        assert_eq!(rebuilt.code_patch_commitment(), public.code_patch_commitment());
    }

    #[rstest::rstest]
    #[case::distinct(false)]
    #[case::duplicate(true)]
    fn mock_block_logs_preserve_grouping_and_private_headers(#[case] duplicate: bool) {
        use crate::block::BlockBody;
        use crate::errors::BlockBodyError;

        let first = public_header(1);
        let private = TransactionHeader::mock(2);
        let second = if duplicate { first.clone() } else { public_header(3) };
        let (batches, logs) = PublicTransactionLogs::mock_for_block(vec![
            OrderedTransactionHeaders::new_unchecked(vec![first, private.clone()]),
            OrderedTransactionHeaders::new_unchecked(vec![second]),
        ]);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].as_slice().len(), 2);
        assert_eq!(batches[1].as_slice().len(), 1);
        assert_eq!(batches[0].as_slice()[1], private);
        assert!(logs.entries().iter().all(|(_, records)| !records.is_empty()));
        let first_id = batches[0].as_slice()[0].id();
        assert_eq!(logs.entries()[0].0, first_id);
        if duplicate {
            assert_eq!(logs.entries().len(), 1);
            assert_eq!(batches[1].as_slice()[0].id(), first_id);
            assert!(matches!(BlockBody::new(vec![], vec![], vec![], batches, logs),
                Err(BlockBodyError::DuplicateTransaction(id)) if id == first_id));
        } else {
            assert_eq!(logs.entries().len(), 2);
            assert_eq!(logs.entries()[1].0, batches[1].as_slice()[0].id());
            logs.validate(batches.iter().flat_map(OrderedTransactionHeaders::as_slice))
                .unwrap();
            BlockBody::new(vec![], vec![], vec![], batches, logs).unwrap();
        }
    }
}
