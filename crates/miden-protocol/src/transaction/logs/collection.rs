use alloc::string::ToString;
use alloc::vec::Vec;

use super::{TransactionLogData, TransactionLogDataError};
use crate::transaction::OrderedTransactionHeaders;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{
    MAX_LOG_DATA_BYTES_PER_BATCH,
    MAX_LOG_DATA_BYTES_PER_BLOCK,
    MAX_LOG_DATA_TRANSACTIONS_PER_BATCH,
    MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
    MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
    MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
    MAX_PUBLIC_LOGS_PER_BATCH,
    MAX_PUBLIC_LOGS_PER_BLOCK,
};

/// Submitted log data in transaction-header order, including empty collections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionLogDataCollection(Vec<TransactionLogData>);

#[derive(Clone, Copy)]
enum LogDataScope {
    Batch,
    Block,
}

struct LogDataBudget {
    entries: usize,
    bytes: usize,
    logs: usize,
    words: usize,
}

impl LogDataScope {
    fn budget(self) -> LogDataBudget {
        match self {
            Self::Batch => LogDataBudget {
                entries: MAX_LOG_DATA_TRANSACTIONS_PER_BATCH,
                bytes: MAX_LOG_DATA_BYTES_PER_BATCH - 4,
                logs: MAX_PUBLIC_LOGS_PER_BATCH,
                words: MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH,
            },
            Self::Block => LogDataBudget {
                entries: MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK,
                bytes: MAX_LOG_DATA_BYTES_PER_BLOCK - 4,
                logs: MAX_PUBLIC_LOGS_PER_BLOCK,
                words: MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK,
            },
        }
    }
}

impl LogDataBudget {
    fn consume(&mut self, data: &TransactionLogData) -> Result<(), TransactionLogDataError> {
        self.entries =
            self.entries.checked_sub(1).ok_or(TransactionLogDataError::AggregateBudget)?;
        self.bytes = self
            .bytes
            .checked_sub(4 + data.get_size_hint())
            .ok_or(TransactionLogDataError::AggregateBudget)?;
        if let TransactionLogData::Public(logs) = data {
            self.logs = self
                .logs
                .checked_sub(logs.num_logs())
                .ok_or(TransactionLogDataError::AggregateBudget)?;
            let words = logs.iter().map(|log| log.num_payload_words()).sum();
            self.words =
                self.words.checked_sub(words).ok_or(TransactionLogDataError::AggregateBudget)?;
        }
        Ok(())
    }
}

impl TransactionLogDataCollection {
    /// Checks block resource limits. Call [`Self::validate_for_block`] or
    /// [`Self::validate_for_batch`] to check header associations.
    pub fn new(data: Vec<TransactionLogData>) -> Result<Self, TransactionLogDataError> {
        let collection = Self(data);
        Self::validate_block_budget(collection.0.iter())?;
        Ok(collection)
    }

    /// Returns entries in transaction order.
    pub fn as_slice(&self) -> &[TransactionLogData] {
        &self.0
    }

    /// Consumes the entries in transaction order.
    pub fn into_vec(self) -> Vec<TransactionLogData> {
        self.0
    }

    /// Checks header associations, visibility, commitments, and batch limits.
    pub fn validate_for_batch(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogDataError> {
        Self::validate_batch_budget(self.0.iter())?;
        self.validate_headers(headers)
    }

    /// Checks header associations, visibility, commitments, and block limits.
    pub fn validate_for_block(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogDataError> {
        Self::validate_block_budget(self.0.iter())?;
        self.validate_headers(headers)
    }

    fn validate_headers(
        &self,
        headers: &OrderedTransactionHeaders,
    ) -> Result<(), TransactionLogDataError> {
        if self.0.len() != headers.as_slice().len() {
            return Err(TransactionLogDataError::AssociationCount);
        }
        for (index, (data, header)) in self.0.iter().zip(headers.as_slice()).enumerate() {
            data.validate_visibility(header.account_id())?;
            if data.commitment() != header.logs_commitment() {
                return Err(TransactionLogDataError::CommitmentMismatch(index));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_batch_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogData>,
    ) -> Result<(), TransactionLogDataError> {
        Self::validate_budget(entries, LogDataScope::Batch)
    }

    pub(crate) fn validate_block_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogData>,
    ) -> Result<(), TransactionLogDataError> {
        Self::validate_budget(entries, LogDataScope::Block)
    }

    fn validate_budget<'a>(
        entries: impl IntoIterator<Item = &'a TransactionLogData>,
        scope: LogDataScope,
    ) -> Result<(), TransactionLogDataError> {
        let mut budget = scope.budget();
        for data in entries {
            budget.consume(data)?;
        }
        Ok(())
    }

    /// Builds empty fixture data and refuses headers that commit to nonempty logs.
    #[cfg(any(test, feature = "testing"))]
    pub fn empty_for_headers(headers: &OrderedTransactionHeaders) -> Self {
        Self(
            headers
                .as_slice()
                .iter()
                .map(|header| {
                    assert!(
                        header.logs_commitment().is_empty(),
                        "fixture header has nonempty logs"
                    );
                    if header.account_id().is_public() {
                        TransactionLogData::Public(Default::default())
                    } else {
                        TransactionLogData::Private(crate::Word::empty())
                    }
                })
                .collect(),
        )
    }
}

impl Serializable for TransactionLogDataCollection {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.0.len() as u32);
        for data in &self.0 {
            target.write_u32(data.get_size_hint() as u32);
            data.write_into(target);
        }
    }

    fn get_size_hint(&self) -> usize {
        4 + self.0.iter().map(|data| 4 + data.get_size_hint()).sum::<usize>()
    }
}

impl Deserializable for TransactionLogDataCollection {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_u32()? as usize;
        if count > MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK {
            return Err(DeserializationError::InvalidValue("too many log data entries".into()));
        }
        let mut budget = LogDataScope::Block.budget();
        let mut data = Vec::new();
        for _ in 0..count {
            let size = source.read_u32()? as usize;
            if budget.bytes.checked_sub(4).is_none_or(|remaining| size > remaining) {
                return Err(DeserializationError::InvalidValue(
                    "log data exceeds block byte budget".into(),
                ));
            }
            // A transaction can encode at most 64 records with 512 payload words in total.
            // Reject oversized frames before reading or allocating their payloads.
            let max_tx_size = 3
                + crate::MAX_LOGS_PER_TX * super::TransactionLog::min_serialized_size()
                + crate::MAX_LOG_PAYLOAD_WORDS_PER_TX * crate::Word::SERIALIZED_SIZE;
            if size > max_tx_size {
                return Err(DeserializationError::InvalidValue(
                    "log data frame exceeds transaction limit".into(),
                ));
            }
            let encoded = source.read_slice(size)?;
            let entry = TransactionLogData::read_from_bytes(encoded)?;
            if entry.get_size_hint() != size {
                return Err(DeserializationError::InvalidValue(
                    "noncanonical log data frame".into(),
                ));
            }
            budget
                .consume(&entry)
                .map_err(|error| DeserializationError::InvalidValue(error.to_string()))?;
            data.push(entry);
        }
        Self::new(data).map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Word;
    use crate::account::AccountId;
    use crate::block::BlockBody;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    };
    use crate::transaction::{
        InputNotes,
        LogTopic,
        TransactionHeader,
        TransactionLog,
        TransactionLogs,
    };

    fn public_log(words: usize) -> TransactionLog {
        TransactionLog::new(
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
            LogTopic::from_name("test::updated"),
            vec![Word::from([17u32; 4]); words],
        )
        .unwrap()
    }

    fn header(account: AccountId, data: &TransactionLogData, state: u32) -> TransactionHeader {
        TransactionHeader::new(
            account,
            Word::from([state; 4]),
            Word::from([state + 1; 4]),
            InputNotes::default(),
            vec![],
            data.commitment(),
        )
        .unwrap()
    }

    #[test]
    fn block_logs_roundtrip_and_validate_associations() {
        let public = TransactionLogData::Public(
            TransactionLogs::new(vec![public_log(1), public_log(1)]).unwrap(),
        );
        let private = TransactionLogData::Private(Word::from([73u32; 4]));
        let headers = OrderedTransactionHeaders::new_unchecked(vec![
            header(
                ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into().unwrap(),
                &public,
                1,
            ),
            header(ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(), &private, 3),
        ]);
        let data =
            TransactionLogDataCollection::new(vec![public.clone(), private.clone()]).unwrap();
        let block = BlockBody::new(vec![], vec![], vec![], data.clone(), headers.clone()).unwrap();
        assert_eq!(BlockBody::read_from_bytes(&block.to_bytes()).unwrap(), block);
        for entries in [
            vec![],
            vec![public.clone()],
            vec![public.clone(), private.clone(), private.clone()],
            vec![private, public],
        ] {
            let invalid = TransactionLogDataCollection::new(entries).unwrap();
            assert!(BlockBody::new(vec![], vec![], vec![], invalid, headers.clone()).is_err());
        }
        let changed = TransactionLogDataCollection::new(vec![
            TransactionLogData::Public(TransactionLogs::new(vec![public_log(2)]).unwrap()),
            data.as_slice()[1].clone(),
        ])
        .unwrap();
        assert_eq!(
            changed.validate_for_block(&headers),
            Err(TransactionLogDataError::CommitmentMismatch(0))
        );
        let duplicate_headers =
            OrderedTransactionHeaders::new_unchecked(vec![headers.as_slice()[0].clone(); 2]);
        let duplicate_data =
            TransactionLogDataCollection::new(vec![data.as_slice()[0].clone(); 2]).unwrap();
        assert!(BlockBody::new(vec![], vec![], vec![], duplicate_data, duplicate_headers).is_err());
    }

    #[test]
    fn aggregate_limits_accept_the_boundary_and_reject_one_more() {
        let full_payload = TransactionLogData::Public(
            TransactionLogs::new(vec![public_log(crate::MAX_LOG_PAYLOAD_WORDS); 2]).unwrap(),
        );
        let full_records = TransactionLogData::Public(
            TransactionLogs::new(vec![public_log(0); crate::MAX_LOGS_PER_TX]).unwrap(),
        );
        let one_record =
            TransactionLogData::Public(TransactionLogs::new(vec![public_log(1)]).unwrap());
        for scope in [LogDataScope::Batch, LogDataScope::Block] {
            let limits = scope.budget();
            for (entry, count, extra) in [
                (
                    full_payload.clone(),
                    limits.words / crate::MAX_LOG_PAYLOAD_WORDS_PER_TX,
                    one_record.clone(),
                ),
                (full_records.clone(), limits.logs / crate::MAX_LOGS_PER_TX, one_record.clone()),
                (
                    TransactionLogData::Private(Word::empty()),
                    limits.entries,
                    TransactionLogData::Private(Word::empty()),
                ),
                (
                    TransactionLogData::Public(TransactionLogs::default()),
                    limits.entries,
                    TransactionLogData::Public(TransactionLogs::default()),
                ),
            ] {
                let mut entries = vec![entry; count];
                assert!(
                    TransactionLogDataCollection::validate_budget(entries.iter(), scope).is_ok()
                );
                let data = TransactionLogDataCollection::new(entries.clone()).unwrap();
                let encoded = data.to_bytes();
                assert_eq!(encoded.len(), data.get_size_hint());
                assert_eq!(TransactionLogDataCollection::read_from_bytes(&encoded).unwrap(), data);
                entries.push(extra);
                assert_eq!(
                    TransactionLogDataCollection::validate_budget(entries.iter(), scope),
                    Err(TransactionLogDataError::AggregateBudget)
                );
            }
        }
    }

    #[test]
    fn decoder_stops_when_public_resources_are_exhausted() {
        for (entry, count) in [
            (
                TransactionLogData::Public(
                    TransactionLogs::new(vec![public_log(0); crate::MAX_LOGS_PER_TX]).unwrap(),
                ),
                MAX_PUBLIC_LOGS_PER_BLOCK / crate::MAX_LOGS_PER_TX,
            ),
            (
                TransactionLogData::Public(
                    TransactionLogs::new(vec![public_log(crate::MAX_LOG_PAYLOAD_WORDS); 2])
                        .unwrap(),
                ),
                MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK / crate::MAX_LOG_PAYLOAD_WORDS_PER_TX,
            ),
        ] {
            let mut bytes = Vec::new();
            bytes.write_u32(count as u32 + 2);
            for _ in 0..=count {
                bytes.write_u32(entry.get_size_hint() as u32);
                entry.write_into(&mut bytes);
            }
            // The next frame is absent. Reject the exhausted budget before trying to read it.
            assert_eq!(
                TransactionLogDataCollection::read_from_bytes(&bytes),
                Err(DeserializationError::InvalidValue(
                    TransactionLogDataError::AggregateBudget.to_string()
                ))
            );
        }
    }

    #[test]
    fn malformed_frames_fail_before_reading_the_declared_payload() {
        let mut bytes = Vec::new();
        bytes.write_u32(MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK as u32 + 1);
        assert!(matches!(
            TransactionLogDataCollection::read_from_bytes(&bytes),
            Err(DeserializationError::InvalidValue(_))
        ));
        bytes.clear();
        bytes.write_u32(1);
        bytes.write_u32(u32::MAX);
        assert!(matches!(
            TransactionLogDataCollection::read_from_bytes(&bytes),
            Err(DeserializationError::InvalidValue(_))
        ));
        let entry = TransactionLogData::Private(Word::empty());
        bytes.clear();
        bytes.write_u32(1);
        bytes.write_u32(entry.get_size_hint() as u32 + 1);
        entry.write_into(&mut bytes);
        bytes.push(0);
        assert!(matches!(
            TransactionLogDataCollection::read_from_bytes(&bytes),
            Err(DeserializationError::InvalidValue(_))
        ));
    }
}
