use alloc::vec::Vec;

use super::{TransactionLog, TransactionLogError, TransactionLogs};
use crate::account::AccountId;
use crate::crypto::SequentialCommit;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

/// Submitted transaction log data for the account against which the transaction executes.
///
/// A public native account submits complete transaction logs. A private native account submits
/// only their commitment. This applies to all transaction logs, including those emitted by
/// foreign accounts during FPI.
///
/// Validating a private transaction log commitment requires the transaction proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionLogDetails {
    /// A commitment to the private transaction logs.
    Private(Word),
    /// Complete public transaction logs, from which the commitment is derived.
    Public(TransactionLogs),
}

impl TransactionLogDetails {
    const PRIVATE_ID: u8 = 0;
    const PUBLIC_ID: u8 = 1;

    /// Returns the computed public or supplied private transaction log commitment.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the public log commitments or the supplied private commitment as field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Checks that public transaction logs are submitted for a public native account and a
    /// private commitment is submitted for a private native account.
    ///
    /// `native_account` is the account against which the transaction executes. A public foreign
    /// account emitting transaction logs during FPI does not make a private transaction public.
    pub(crate) fn validate_visibility(
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

    /// Returns the maximum encoded size of a public or private entry, including its visibility tag.
    pub(super) fn max_serialized_size() -> usize {
        let max_public_size = TransactionLogs::min_serialized_size()
            + TransactionLogs::MAX_COUNT * TransactionLog::min_serialized_size()
            + TransactionLogs::MAX_NUM_WORDS * Word::SERIALIZED_SIZE;
        size_of::<u8>() + max_public_size.max(Word::SERIALIZED_SIZE)
    }
}

impl SequentialCommit for TransactionLogDetails {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        match self {
            Self::Private(commitment) => commitment.as_elements().to_vec(),
            Self::Public(logs) => logs.to_elements(),
        }
    }

    fn to_commitment(&self) -> Word {
        match self {
            Self::Private(commitment) => *commitment,
            Self::Public(logs) => logs.commitment(),
        }
    }
}

impl Serializable for TransactionLogDetails {
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

impl Deserializable for TransactionLogDetails {
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
