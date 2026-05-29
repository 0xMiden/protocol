use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::Word;
use crate::crypto::merkle::MerkleError;
#[cfg(feature = "std")]
use crate::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage, SmtStorageReader};
use crate::crypto::merkle::smt::{LeafIndex, MutationSet, SMT_DEPTH, Smt, SmtLeaf, SmtProof};

// SMT BACKEND READER
// ================================================================================================

/// Abstracts over the read-only operations of the different SMT backends (e.g. [`Smt`] and
/// [`LargeSmt`]), so that the block trees can work with either implementation transparently.
///
/// This trait is value-agnostic: leaves are stored as raw [`Word`]s. Trees that wrap a more
/// specific value type (such as the nullifier tree) are responsible for converting to and from
/// [`Word`] in their own accessors.
///
/// The method set is intentionally the superset required by both the account and nullifier trees,
/// so a given tree only uses the subset relevant to it (e.g. the account tree iterates [`leaves`],
/// the nullifier tree iterates [`entries`]).
///
/// This trait contains only read-only methods. For write methods, see [`SmtBackend`].
pub trait SmtBackendReader: Sized {
    type Error: core::error::Error + Send + 'static;

    /// Returns the number of leaves in the SMT.
    fn num_leaves(&self) -> usize;

    /// Returns the number of key-value entries in the SMT.
    ///
    /// This can exceed [`Self::num_leaves`] when keys collide into the same leaf.
    fn num_entries(&self) -> usize;

    /// Returns all leaves in the SMT as an iterator over leaf index and leaf pairs.
    fn leaves(&self) -> Box<dyn Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)> + '_>;

    /// Returns all key-value entries in the SMT.
    fn entries(&self) -> Box<dyn Iterator<Item = (Word, Word)> + '_>;

    /// Opens the leaf at the given key, returning a Merkle proof.
    fn open(&self, key: &Word) -> SmtProof;

    /// Returns the value associated with the given key.
    fn get_value(&self, key: &Word) -> Word;

    /// Returns the leaf at the given key.
    fn get_leaf(&self, key: &Word) -> SmtLeaf;

    /// Returns the root of the SMT.
    fn root(&self) -> Word;
}

// SMT BACKEND
// ================================================================================================

/// Extension trait for [`SmtBackendReader`] that provides write methods.
pub trait SmtBackend: SmtBackendReader {
    /// Computes the mutation set required to apply the given updates to the SMT.
    fn compute_mutations(
        &self,
        updates: Vec<(Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error>;

    /// Applies the given mutation set to the SMT.
    fn apply_mutations(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), Self::Error>;

    /// Applies the given mutation set to the SMT and returns the reverse mutation set.
    ///
    /// The reverse mutation set can be used to revert the changes made by this operation.
    fn apply_mutations_with_reversion(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error>;

    /// Inserts a key-value pair into the SMT, returning the previous value at that key.
    fn insert(&mut self, key: Word, value: Word) -> Result<Word, Self::Error>;
}

// BACKEND READER IMPLEMENTATION FOR SMT
// ================================================================================================

impl SmtBackendReader for Smt {
    type Error = MerkleError;

    fn num_leaves(&self) -> usize {
        Smt::num_leaves(self)
    }

    fn num_entries(&self) -> usize {
        Smt::num_entries(self)
    }

    fn leaves(&self) -> Box<dyn Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)> + '_> {
        Box::new(Smt::leaves(self).map(|(idx, leaf)| (idx, leaf.clone())))
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (Word, Word)> + '_> {
        Box::new(Smt::entries(self).map(|(k, v)| (*k, *v)))
    }

    fn open(&self, key: &Word) -> SmtProof {
        Smt::open(self, key)
    }

    fn get_value(&self, key: &Word) -> Word {
        Smt::get_value(self, key)
    }

    fn get_leaf(&self, key: &Word) -> SmtLeaf {
        Smt::get_leaf(self, key)
    }

    fn root(&self) -> Word {
        Smt::root(self)
    }
}

// BACKEND WRITER IMPLEMENTATION FOR SMT
// ================================================================================================

impl SmtBackend for Smt {
    fn compute_mutations(
        &self,
        updates: Vec<(Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        Smt::compute_mutations(self, updates)
    }

    fn apply_mutations(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), Self::Error> {
        Smt::apply_mutations(self, set)
    }

    fn apply_mutations_with_reversion(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        Smt::apply_mutations_with_reversion(self, set)
    }

    fn insert(&mut self, key: Word, value: Word) -> Result<Word, Self::Error> {
        Smt::insert(self, key, value)
    }
}

// BACKEND READER IMPLEMENTATION FOR LARGE SMT
// ================================================================================================

#[cfg(feature = "std")]
impl<Backend> SmtBackendReader for LargeSmt<Backend>
where
    Backend: SmtStorageReader,
{
    type Error = MerkleError;

    fn num_leaves(&self) -> usize {
        LargeSmt::num_leaves(self)
    }

    fn num_entries(&self) -> usize {
        LargeSmt::num_entries(self)
    }

    fn leaves(&self) -> Box<dyn Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)> + '_> {
        Box::new(LargeSmt::leaves(self).expect("Only IO can error out here"))
    }

    fn entries(&self) -> Box<dyn Iterator<Item = (Word, Word)> + '_> {
        // SAFETY: We expect here as only I/O errors can occur. Storage failures are considered
        // unrecoverable at this layer. See issue #2010 for future error handling improvements.
        Box::new(LargeSmt::entries(self).expect("Storage I/O error accessing entries"))
    }

    fn open(&self, key: &Word) -> SmtProof {
        LargeSmt::open(self, key)
    }

    fn get_value(&self, key: &Word) -> Word {
        LargeSmt::get_value(self, key)
    }

    fn get_leaf(&self, key: &Word) -> SmtLeaf {
        LargeSmt::get_leaf(self, key)
    }

    fn root(&self) -> Word {
        LargeSmt::root(self)
    }
}

// BACKEND WRITER IMPLEMENTATION FOR LARGE SMT
// ================================================================================================

#[cfg(feature = "std")]
impl<Backend> SmtBackend for LargeSmt<Backend>
where
    Backend: SmtStorage,
{
    fn compute_mutations(
        &self,
        updates: Vec<(Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        LargeSmt::compute_mutations(self, updates).map_err(large_smt_error_to_merkle_error)
    }

    fn apply_mutations(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), Self::Error> {
        LargeSmt::apply_mutations(self, set).map_err(large_smt_error_to_merkle_error)
    }

    fn apply_mutations_with_reversion(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        LargeSmt::apply_mutations_with_reversion(self, set).map_err(large_smt_error_to_merkle_error)
    }

    fn insert(&mut self, key: Word, value: Word) -> Result<Word, Self::Error> {
        LargeSmt::insert(self, key, value)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a [`LargeSmtError`] into a [`MerkleError`].
///
/// Storage failures are treated as unrecoverable at this layer and cause a panic. See issue #2010
/// for future error handling improvements.
#[cfg(feature = "std")]
pub(crate) fn large_smt_error_to_merkle_error(err: LargeSmtError) -> MerkleError {
    match err {
        LargeSmtError::Storage(storage_err) => {
            panic!("Storage error encountered: {:?}", storage_err)
        },
        LargeSmtError::StorageNotEmpty => {
            panic!("StorageNotEmpty error encountered: {:?}", err)
        },
        LargeSmtError::Merkle(merkle_err) => merkle_err,
        LargeSmtError::RootMismatch { expected, actual } => MerkleError::ConflictingRoots {
            expected_root: expected,
            actual_root: actual,
        },
    }
}
