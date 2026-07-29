use alloc::string::String;

use miden_crypto_derive::WordWrapper;

use crate::Word;
use crate::account::AccountId;
use crate::transaction::{OrderedTransactionHeaders, ProvenTransaction, TransactionId};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// BATCH ID
// ================================================================================================

/// Uniquely identifies a batch of transactions, i.e. both
/// [`ProposedBatch`](crate::batch::ProposedBatch) and [`ProvenBatch`](crate::batch::ProvenBatch).
///
/// This is a sequential hash of the tuple `(TRANSACTION_ID || [account_id_suffix,
/// account_id_prefix, 0, 0])` of all transactions and the accounts their executed against in the
/// batch.
#[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd, Hash, WordWrapper)]
pub struct BatchId(Word);

impl BatchId {
    /// Calculates a batch ID from the given set of transactions.
    pub fn from_transactions<'tx, T>(txs: T) -> Self
    where
        T: Iterator<Item = &'tx ProvenTransaction>,
    {
        Self::from_ids(txs.map(|tx| (tx.id(), tx.account_id())))
    }

    /// Calculates a batch ID from the given transaction ID and account ID tuple.
    pub fn from_ids(iter: impl IntoIterator<Item = (TransactionId, AccountId)>) -> Self {
        // A batch ID commits to the set of transaction it contains which is the same computation as
        // in OrderedTransactionHeaders, so it is reused.
        Self(OrderedTransactionHeaders::compute_commitment(iter))
    }
}

impl core::fmt::Display for BatchId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for BatchId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for BatchId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(Word::read_from(source)?))
    }
}
