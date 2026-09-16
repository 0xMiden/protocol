use super::{TransactionLogDataError, TransactionLogs};
use crate::Word;
use crate::account::AccountId;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// Log data supplied with a submitted transaction.
///
/// Public data contains full records; private data contains only a commitment. Visibility checks
/// use the native account, including for foreign-account logs and empty collections.
///
/// This type stores private commitments as supplied. Deserialization validates the encoding;
/// it does not derive a private commitment or verify a transaction proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionLogData {
    /// Complete public records, with their commitment derived from the records.
    Public(TransactionLogs),
    /// A supplied commitment without private records or opening data.
    Private(Word),
}

impl TransactionLogData {
    const PUBLIC: u8 = 0;
    const PRIVATE: u8 = 1;

    /// Returns the computed public commitment or the supplied private commitment.
    pub fn commitment(&self) -> Word {
        match self {
            Self::Public(logs) => logs.commitment(),
            Self::Private(commitment) => *commitment,
        }
    }

    /// Checks visibility against the native transaction account, not an FPI emitter.
    pub fn validate_visibility(
        &self,
        native_account: AccountId,
    ) -> Result<(), TransactionLogDataError> {
        if matches!(self, Self::Public(_)) == native_account.is_public() {
            Ok(())
        } else {
            Err(TransactionLogDataError::VisibilityMismatch)
        }
    }
}

impl Serializable for TransactionLogData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Public(logs) => {
                target.write_u8(Self::PUBLIC);
                logs.write_into(target);
            },
            Self::Private(commitment) => {
                target.write_u8(Self::PRIVATE);
                commitment.write_into(target);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        1 + match self {
            Self::Public(logs) => logs.get_size_hint(),
            Self::Private(_) => Word::SERIALIZED_SIZE,
        }
    }
}

impl Deserializable for TransactionLogData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            Self::PUBLIC => Ok(Self::Public(TransactionLogs::read_from(source)?)),
            Self::PRIVATE => Ok(Self::Private(Word::read_from(source)?)),
            tag => Err(DeserializationError::InvalidValue(format!(
                "invalid transaction log data tag: {tag}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        1 + TransactionLogs::min_serialized_size()
    }
}
