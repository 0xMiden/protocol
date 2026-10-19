use alloc::vec::Vec;

use miden_crypto_derive::WordWrapper;

use crate::account::AccountId;
use crate::transaction::{OrderedTransactionHeaders, ProvenTransaction, TransactionId};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

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

    /// Computes the sequential commitment to the provided ordered batch IDs.
    ///
    /// This is the `BATCHES_COMMITMENT` public input of the block kernel. It commits to both the
    /// set of batches in a block and the order in which they appear.
    pub fn compute_batches_commitment(batch_ids: impl IntoIterator<Item = BatchId>) -> Word {
        Hasher::hash_elements(&Self::batch_ids_to_elements(batch_ids))
    }

    /// Returns the provided ordered batch IDs represented as a vector of field elements.
    pub(crate) fn batch_ids_to_elements(batch_ids: impl IntoIterator<Item = BatchId>) -> Vec<Felt> {
        let mut elements = Vec::new();
        for batch_id in batch_ids {
            elements.extend_from_slice(batch_id.as_word().as_elements());
        }

        elements
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
