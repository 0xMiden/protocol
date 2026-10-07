use super::{TransactionLogError, TransactionLogs};
use crate::Word;
use crate::account::AccountId;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

/// Submitted transaction log data for the account against which the transaction executes.
///
/// A public native account submits complete transaction logs. A private native account submits
/// only their commitment. This applies to all transaction logs, including those emitted by
/// foreign accounts during FPI.
///
/// Validating a private transaction log commitment requires the transaction proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionLogData {
    /// Complete public transaction logs, from which the commitment is derived.
    Public(TransactionLogs),
    /// A commitment to the private transaction logs.
    Private(Word),
}

impl TransactionLogData {
    const PUBLIC_ID: u8 = 0;
    const PRIVATE_ID: u8 = 1;

    /// Returns the computed public or supplied private transaction log commitment.
    pub fn commitment(&self) -> Word {
        match self {
            Self::Public(logs) => logs.commitment(),
            Self::Private(commitment) => *commitment,
        }
    }

    /// Checks that public transaction logs are submitted for a public native account and a
    /// private commitment is submitted for a private native account.
    ///
    /// `native_account` is the account against which the transaction executes. A public foreign
    /// account emitting transaction logs during FPI does not make a private transaction public.
    pub fn validate_visibility(
        &self,
        native_account: AccountId,
    ) -> Result<(), TransactionLogError> {
        let is_public = matches!(self, Self::Public(_));
        if is_public == native_account.is_public() {
            Ok(())
        } else {
            Err(TransactionLogError::VisibilityMismatch)
        }
    }
}

impl Serializable for TransactionLogData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Public(logs) => {
                target.write_u8(Self::PUBLIC_ID);
                logs.write_into(target);
            },
            Self::Private(commitment) => {
                target.write_u8(Self::PRIVATE_ID);
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
            Self::PUBLIC_ID => Ok(Self::Public(TransactionLogs::read_from(source)?)),
            Self::PRIVATE_ID => Ok(Self::Private(Word::read_from(source)?)),
            tag => Err(DeserializationError::InvalidValue(format!(
                "invalid transaction log data tag: {tag}"
            ))),
        }
    }

    fn min_serialized_size() -> usize {
        1 + TransactionLogs::min_serialized_size()
    }
}
