use alloc::vec::Vec;

use crate::batch::{BatchesCommitment, ProvenBatch};
use crate::crypto::SequentialCommit;
use crate::transaction::OrderedTransactionHeaders;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Word};

// ORDERED BATCHES
// ================================================================================================

/// The ordered set of batches in a [`ProposedBlock`](crate::block::ProposedBlock).
///
/// This is a newtype wrapper representing the set of batches in a proposed block. It can only be
/// retrieved from a proposed block. This type exists only to encapsulate the conversion to
/// [`OrderedTransactionHeaders`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedBatches(Vec<ProvenBatch>);

impl OrderedBatches {
    /// Creates a new set of ordered batches from the provided vector.
    pub fn new(batches: Vec<ProvenBatch>) -> Self {
        Self(batches)
    }

    /// Returns a reference to the underlying proven batches.
    pub fn as_slice(&self) -> &[ProvenBatch] {
        &self.0
    }

    /// Returns the ordered transaction headers of each batch, in the order of the batches.
    pub fn to_transactions(&self) -> Vec<OrderedTransactionHeaders> {
        self.0.iter().map(|batch| batch.transactions().clone()).collect()
    }

    /// Consumes self and returns the ordered transaction headers of each batch, in the order of
    /// the batches.
    pub fn into_transactions(self) -> Vec<OrderedTransactionHeaders> {
        self.0.into_iter().map(ProvenBatch::into_transactions).collect()
    }

    /// Returns the sum of created notes across all batches.
    pub fn num_created_notes(&self) -> usize {
        self.0.as_slice().iter().fold(0, |acc, batch| acc + batch.output_notes().len())
    }

    /// Consumes self and returns the underlying vector of batches.
    pub fn into_vec(self) -> Vec<ProvenBatch> {
        self.0
    }
}

impl SequentialCommit for OrderedBatches {
    type Commitment = Word;

    /// Returns batch IDs represented as a vector of field elements, in order.
    fn to_elements(&self) -> Vec<Felt> {
        BatchesCommitment::batch_ids_to_elements(self.0.iter().map(ProvenBatch::id))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for OrderedBatches {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target)
    }
}

impl Deserializable for OrderedBatches {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read().map(OrderedBatches::new)
    }
}
