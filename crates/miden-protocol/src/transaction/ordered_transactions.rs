use alloc::vec::Vec;

use crate::account::AccountId;
use crate::transaction::{TransactionHeader, TransactionId};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word};

// ORDERED TRANSACTION HEADERS
// ================================================================================================

/// The ordered set of transaction headers in a [`ProvenBatch`](crate::batch::ProvenBatch) or
/// [`ProvenBlock`](crate::block::ProvenBlock).
///
/// This is a newtype wrapper representing either:
/// - the set of transactions in a **batch**,
/// - or the flattened sets of transactions of each proven batch in a **block**.
///
/// This type cannot be constructed directly, but can be retrieved through:
/// - [`ProposedBatch::transaction_headers`](crate::batch::ProposedBatch::transaction_headers),
/// - [`OrderedBatches::into_transactions`](crate::batch::OrderedBatches::into_transactions).
///
/// The rationale for this requirement is that it allows a client to cheaply validate the
/// correctness of the transactions in a proven block returned by a remote prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedTransactionHeaders(Vec<TransactionHeader>);

impl OrderedTransactionHeaders {
    /// Creates a new set of ordered transaction headers from the provided vector.
    ///
    /// # Warning
    ///
    /// See the type-level documentation for the requirements of the passed transactions.
    pub fn new_unchecked(transactions: Vec<TransactionHeader>) -> Self {
        Self(transactions)
    }

    /// Computes a commitment to the list of transactions.
    ///
    /// This is a sequential hash over each transaction's ID and its account ID.
    pub fn commitment(&self) -> Word {
        Self::compute_commitment(self.0.as_slice().iter().map(|tx| (tx.id(), tx.account_id())))
    }

    /// Returns a reference to the underlying transaction headers.
    pub fn as_slice(&self) -> &[TransactionHeader] {
        &self.0
    }

    /// Consumes self and returns the underlying vector of transaction headers.
    pub fn into_vec(self) -> Vec<TransactionHeader> {
        self.0
    }

    // PUBLIC HELPERS
    // --------------------------------------------------------------------------------------------

    /// Computes a commitment to the provided list of transactions.
    ///
    /// Each transaction is represented by a transaction ID and an account ID which it was executed
    /// against. The commitment is a sequential hash over (TRANSACTION_ID, ACCOUNT_ID) tuples.
    pub(crate) fn compute_commitment(
        transactions: impl IntoIterator<Item = (TransactionId, AccountId)>,
    ) -> Word {
        Hasher::hash_elements(&Self::hash_input_elements(transactions))
    }

    /// Returns the felt sequence that [`Self::compute_commitment`] hashes.
    ///
    /// The layout is, for each `(transaction_id, account_id)` pair in iteration order:
    ///   `[transaction_id[4], account_id_suffix, account_id_prefix, 0, 0]`
    ///
    /// The batch kernel pipes this same felt sequence from the advice provider to memory and
    /// asserts the resulting hash matches the public input `BATCH_ID`.
    pub(crate) fn hash_input_elements(
        transactions: impl IntoIterator<Item = (TransactionId, AccountId)>,
    ) -> Vec<Felt> {
        let mut elements = vec![];
        for (transaction_id, account_id) in transactions {
            elements.extend_from_slice(transaction_id.as_elements());
            elements.extend_from_slice(&[
                account_id.suffix(),
                account_id.prefix().as_felt(),
                Felt::ZERO,
                Felt::ZERO,
            ]);
        }
        elements
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for OrderedTransactionHeaders {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target)
    }
}

impl Deserializable for OrderedTransactionHeaders {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read().map(OrderedTransactionHeaders::new_unchecked)
    }
}
