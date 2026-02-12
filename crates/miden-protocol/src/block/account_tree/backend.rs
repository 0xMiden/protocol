use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{AccountId, AccountIdPrefix, AccountTree, AccountTreeError, account_id_to_smt_key};
use crate::Word;
use crate::crypto::merkle::MerkleError;
#[cfg(feature = "std")]
use crate::crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};
use crate::crypto::merkle::smt::{LeafIndex, MutationSet, SMT_DEPTH, Smt, SmtLeaf, SmtProof};

// ACCOUNT TREE BACKEND
// ================================================================================================

/// This trait abstracts over different SMT backends (e.g., `Smt` and `LargeSmt`) to allow
/// the `AccountTree` to work with either implementation transparently.
///
/// Implementors must provide `Default` for creating empty instances. Users should
/// instantiate the backend directly (potentially with entries) and then pass it to
/// [`AccountTree::new`].
pub trait AccountTreeBackend: Sized {
    type Error: core::error::Error + Send + 'static;

    /// Returns the number of leaves in the SMT.
    fn num_leaves(&self) -> usize;

    /// Returns all leaves in the SMT as an iterator over leaf index and leaf pairs.
    fn leaves<'a>(&'a self) -> Box<dyn 'a + Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)>>;

    /// Opens the leaf at the given key, returning a Merkle proof.
    fn open(&self, key: &Word) -> SmtProof;

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

    /// Computes the mutation set required to apply the given updates to the SMT.
    fn compute_mutations(
        &self,
        updates: Vec<(Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error>;

    /// Inserts a key-value pair into the SMT, returning the previous value at that key.
    fn insert(&mut self, key: Word, value: Word) -> Result<Word, Self::Error>;

    /// Returns the value associated with the given key.
    fn get_value(&self, key: &Word) -> Word;

    /// Returns the leaf at the given key.
    fn get_leaf(&self, key: &Word) -> SmtLeaf;

    /// Returns the root of the SMT.
    fn root(&self) -> Word;
}

// BACKEND IMPLEMENTATION FOR SMT
// ================================================================================================

impl AccountTreeBackend for Smt {
    type Error = MerkleError;

    fn num_leaves(&self) -> usize {
        Smt::num_leaves(self)
    }

    fn leaves<'a>(&'a self) -> Box<dyn 'a + Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)>> {
        Box::new(Smt::leaves(self).map(|(idx, leaf)| (idx, leaf.clone())))
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

    fn apply_mutations_with_reversion(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        Smt::apply_mutations_with_reversion(self, set)
    }

    fn compute_mutations(
        &self,
        updates: Vec<(Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        Smt::compute_mutations(self, updates)
    }

    fn insert(&mut self, key: Word, value: Word) -> Result<Word, Self::Error> {
        Smt::insert(self, key, value)
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

// BACKEND IMPLEMENTATION FOR LARGE SMT
// ================================================================================================

#[cfg(feature = "std")]
impl<Backend> AccountTreeBackend for LargeSmt<Backend>
where
    Backend: SmtStorage,
{
    type Error = MerkleError;

    fn num_leaves(&self) -> usize {
        // LargeSmt::num_leaves returns Result<usize, LargeSmtError>
        // We'll unwrap or return 0 on error
        LargeSmt::num_leaves(self).map_err(large_smt_error_to_merkle_error).unwrap_or(0)
    }

    fn leaves<'a>(&'a self) -> Box<dyn 'a + Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)>> {
        Box::new(LargeSmt::leaves(self).expect("Only IO can error out here"))
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

    fn apply_mutations_with_reversion(
        &mut self,
        set: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        LargeSmt::apply_mutations_with_reversion(self, set).map_err(large_smt_error_to_merkle_error)
    }

    fn compute_mutations(
        &self,
        updates: Vec<(Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, Self::Error> {
        LargeSmt::compute_mutations(self, updates).map_err(large_smt_error_to_merkle_error)
    }

    fn insert(&mut self, key: Word, value: Word) -> Result<Word, Self::Error> {
        LargeSmt::insert(self, key, value)
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

// CONVENIENCE METHODS
// ================================================================================================

impl AccountTree<Smt> {
    /// Creates a new [`AccountTree`] with the provided entries.
    ///
    /// This is a convenience method for testing that creates an SMT backend with the provided
    /// entries and wraps it in an AccountTree. It validates that the entries don't contain
    /// duplicate prefixes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided entries contain duplicate account ID prefixes
    /// - The backend fails to create the SMT with the entries
    pub fn with_entries<I>(
        entries: impl IntoIterator<Item = (AccountId, Word), IntoIter = I>,
    ) -> Result<Self, AccountTreeError>
    where
        I: ExactSizeIterator<Item = (AccountId, Word)>,
    {
        // Create the SMT with the entries
        let smt = Smt::with_entries(
            entries
                .into_iter()
                .map(|(id, commitment)| (account_id_to_smt_key(id), commitment)),
        )
        .map_err(|err| {
            let MerkleError::DuplicateValuesForIndex(leaf_idx) = err else {
                unreachable!("the only error returned by Smt::with_entries is of this type");
            };

            // SAFETY: Since we only inserted account IDs into the SMT, it is guaranteed that
            // the leaf_idx is a valid Felt as well as a valid account ID prefix.
            AccountTreeError::DuplicateStateCommitments {
                prefix: AccountIdPrefix::new_unchecked(
                    crate::Felt::try_from(leaf_idx).expect("leaf index should be a valid felt"),
                ),
            }
        })?;

        AccountTree::new(smt)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(feature = "std")]
fn large_smt_error_to_merkle_error(err: LargeSmtError) -> MerkleError {
    match err {
        LargeSmtError::Storage(storage_err) => {
            panic!("Storage error encountered: {:?}", storage_err)
        },
        LargeSmtError::Merkle(merkle_err) => merkle_err,
    }
}
