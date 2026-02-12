use alloc::boxed::Box;

use super::{BlockNumber, Nullifier, NullifierBlock, NullifierTree, NullifierTreeError};
use crate::Word;
use crate::crypto::merkle::MerkleError;
#[cfg(feature = "std")]
use crate::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};
use crate::crypto::merkle::smt::{MutationSet, SMT_DEPTH, Smt, SmtProof};

// NULLIFIER TREE BACKEND
// ================================================================================================

/// This trait abstracts over different SMT backends (e.g., `Smt` and `LargeSmt`) to allow
/// the `NullifierTree` to work with either implementation transparently.
///
/// Users should instantiate the backend directly (potentially with entries) and then
/// pass it to [`NullifierTree::new_unchecked`].
///
/// # Invariants
///
/// Assumes the provided SMT upholds the guarantees of the [`NullifierTree`]. Specifically:
/// - Nullifiers are only spent once and their block numbers do not change.
/// - Nullifier leaf values must be valid according to [`NullifierBlock`].
pub trait NullifierTreeBackend: Sized {
    type Error: core::error::Error + Send + 'static;

    /// Returns the number of entries in the SMT.
    fn num_entries(&self) -> usize;

    /// Returns all entries in the SMT as an iterator over key-value pairs.
    fn entries(&self) -> Box<dyn Iterator<Item = (Word, Word)> + '_>;

    /// Opens the leaf at the given key, returning a Merkle proof.
    fn open(&self, key: &Word) -> SmtProof;

    /// Applies the given mutation set to the SMT.
    fn apply_mutations(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), Self::Error>;

    /// Computes the mutation set required to apply the given updates to the SMT.
    fn compute_mutations(
        &self,
        updates: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error>;

    /// Inserts a key-value pair into the SMT, returning the previous value at that key.
    fn insert(&mut self, key: Word, value: NullifierBlock) -> Result<NullifierBlock, Self::Error>;

    /// Returns the value associated with the given key.
    fn get_value(&self, key: &Word) -> NullifierBlock;

    /// Returns the root of the SMT.
    fn root(&self) -> Word;
}

// BACKEND IMPLEMENTATION FOR SMT
// ================================================================================================

impl NullifierTreeBackend for Smt {
    type Error = MerkleError;

    fn num_entries(&self) -> usize {
        Smt::num_entries(self)
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (Word, Word)> + '_> {
        Box::new(Smt::entries(self).map(|(k, v)| (*k, *v)))
    }

    fn open(&self, key: &Word) -> SmtProof {
        Smt::open(self, key)
    }

    fn apply_mutations(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), Self::Error> {
        Smt::apply_mutations(self, set)
    }

    fn compute_mutations(
        &self,
        updates: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        Smt::compute_mutations(self, updates)
    }

    fn insert(&mut self, key: Word, value: NullifierBlock) -> Result<NullifierBlock, Self::Error> {
        Smt::insert(self, key, value.into()).map(|word| {
            NullifierBlock::try_from(word).expect("SMT should only store valid NullifierBlocks")
        })
    }

    fn get_value(&self, key: &Word) -> NullifierBlock {
        NullifierBlock::new(Smt::get_value(self, key))
            .expect("SMT should only store valid NullifierBlocks")
    }

    fn root(&self) -> Word {
        Smt::root(self)
    }
}

// NULLIFIER TREE BACKEND FOR LARGE SMT
// ================================================================================================

#[cfg(feature = "std")]
impl<Backend> NullifierTreeBackend for LargeSmt<Backend>
where
    Backend: SmtStorage,
{
    type Error = MerkleError;

    fn num_entries(&self) -> usize {
        // SAFETY: We panic on storage errors here as they represent unrecoverable I/O failures.
        // This maintains API compatibility with the non-fallible Smt::num_entries().
        // See issue #2010 for future improvements to error handling.
        LargeSmt::num_entries(self)
            .map_err(large_smt_error_to_merkle_error)
            .expect("Storage I/O error accessing num_entries")
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (Word, Word)> + '_> {
        // SAFETY: We expect here as only I/O errors can occur. Storage failures are considered
        // unrecoverable at this layer. See issue #2010 for future error handling improvements.
        Box::new(LargeSmt::entries(self).expect("Storage I/O error accessing entries"))
    }

    fn open(&self, key: &Word) -> SmtProof {
        LargeSmt::open(self, key)
    }

    fn apply_mutations(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), Self::Error> {
        LargeSmt::apply_mutations(self, set).map_err(large_smt_error_to_merkle_error)
    }

    fn compute_mutations(
        &self,
        updates: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        LargeSmt::compute_mutations(self, updates).map_err(large_smt_error_to_merkle_error)
    }

    fn insert(&mut self, key: Word, value: NullifierBlock) -> Result<NullifierBlock, Self::Error> {
        LargeSmt::insert(self, key, value.into()).map(|word| {
            NullifierBlock::try_from(word).expect("SMT should only store valid NullifierBlocks")
        })
    }

    fn get_value(&self, key: &Word) -> NullifierBlock {
        LargeSmt::get_value(self, key)
            .try_into()
            .expect("unable to create NullifierBlock")
    }

    fn root(&self) -> Word {
        LargeSmt::root(self)
    }
}

// CONVENIENCE METHODS
// ================================================================================================

impl NullifierTree<Smt> {
    /// Creates a new nullifier tree from the provided entries.
    ///
    /// This is a convenience method that creates an SMT backend with the provided entries and
    /// wraps it in a NullifierTree.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided entries contain multiple block numbers for the same nullifier.
    pub fn with_entries(
        entries: impl IntoIterator<Item = (Nullifier, BlockNumber)>,
    ) -> Result<Self, NullifierTreeError> {
        let leaves = entries.into_iter().map(|(nullifier, block_num)| {
            (nullifier.as_word(), NullifierBlock::from(block_num).into())
        });

        let smt = Smt::with_entries(leaves)
            .map_err(NullifierTreeError::DuplicateNullifierBlockNumbers)?;

        Ok(Self::new_unchecked(smt))
    }
}

#[cfg(feature = "std")]
impl<Backend> NullifierTree<LargeSmt<Backend>>
where
    Backend: SmtStorage,
{
    /// Creates a new nullifier tree from the provided entries using the given storage backend
    ///
    /// This is a convenience method that creates an SMT on the provided storage backend using the
    /// provided entries and wraps it in a NullifierTree.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided entries contain multiple block numbers for the same nullifier.
    /// - a storage error is encountered.
    pub fn with_storage_from_entries(
        storage: Backend,
        entries: impl IntoIterator<Item = (Nullifier, BlockNumber)>,
    ) -> Result<Self, NullifierTreeError> {
        let leaves = entries.into_iter().map(|(nullifier, block_num)| {
            (nullifier.as_word(), NullifierBlock::from(block_num).into())
        });

        let smt = LargeSmt::<Backend>::with_entries(storage, leaves)
            .map_err(large_smt_error_to_merkle_error)
            .map_err(NullifierTreeError::DuplicateNullifierBlockNumbers)?;

        Ok(Self::new_unchecked(smt))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(feature = "std")]
pub(super) fn large_smt_error_to_merkle_error(err: LargeSmtError) -> MerkleError {
    match err {
        LargeSmtError::Storage(storage_err) => {
            panic!("Storage error encountered: {:?}", storage_err)
        },
        LargeSmtError::Merkle(merkle_err) => merkle_err,
    }
}
