use alloc::vec::Vec;

use miden_crypto_derive::WordWrapper;

use crate::batch::BatchId;
use crate::{Felt, Hasher, Word};

// BATCHES COMMITMENT
// ================================================================================================

/// The sequential commitment to the ordered batch IDs of a block.
///
/// This is the `BATCHES_COMMITMENT` public input of the block kernel. It commits to both the set
/// of batches in a block and the order in which they appear.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, WordWrapper)]
pub struct BatchesCommitment(Word);

impl BatchesCommitment {
    /// Computes the commitment to the provided ordered batch IDs.
    pub fn new(batch_ids: impl IntoIterator<Item = BatchId>) -> Self {
        Self(Hasher::hash_elements(&Self::batch_ids_to_elements(batch_ids)))
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

impl core::fmt::Display for BatchesCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
