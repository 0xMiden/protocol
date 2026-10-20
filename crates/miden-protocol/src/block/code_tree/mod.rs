use alloc::collections::BTreeSet;

#[cfg(feature = "std")]
use miden_crypto::merkle::smt::{LargeSmt, LargeSmtError, SmtStorage};

use crate::block::{SmtBackend, SmtBackendReader};
use crate::code::ProcedureRoot;
use crate::crypto::merkle::MerkleError;
use crate::crypto::merkle::smt::{MutationSet, SMT_DEPTH, Smt};
use crate::errors::CodeTreeError;
use crate::{Felt, Word};

mod witness;
pub use witness::CodeWitness;

mod partial;
pub use partial::PartialCodeTree;

mod patch;
pub use patch::CodeTreePatch;

mod dependencies;
pub use dependencies::CodeTreeDependencies;

/// The value of a procedure root that is present in the code tree.
///
/// Absent procedure roots have the [`EMPTY_WORD`] as their value.
const PRESENT_VALUE: Word = Word::new([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);

// CODE TREE
// ================================================================================================

/// The sparse merkle tree of all procedure roots registered in the blockchain.
///
/// It allows proving the presence or absence of a procedure root, which guarantees that code is
/// available and complete and allows deduplicating it across accounts and notes.
///
/// The tree is append-only: once a procedure root is present, it is never removed. Inserting a
/// procedure root that is already present is a no-op rather than an error, because presence may
/// have been proven against an older tree root.
///
/// Procedure roots are arbitrary hashes and so multiple of them can map to the same leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeTree<Backend = Smt> {
    smt: Backend,
}

impl<Backend> Default for CodeTree<Backend>
where
    Backend: Default,
{
    fn default() -> Self {
        Self { smt: Default::default() }
    }
}

impl<Backend> CodeTree<Backend>
where
    Backend: SmtBackendReader<Error = MerkleError>,
{
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The depth of the code tree.
    pub const DEPTH: u8 = SMT_DEPTH;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new `CodeTree` from its inner representation with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the SMT contains a value that does not mark a procedure root as present.
    pub fn new(backend: Backend) -> Result<Self, CodeTreeError> {
        if let Some((key, value)) = backend.entries().find(|(_, value)| *value != PRESENT_VALUE) {
            return Err(CodeTreeError::InvalidLeafValue {
                procedure_root: ProcedureRoot::from_raw(key),
                value,
            });
        }

        Ok(Self::new_unchecked(backend))
    }

    /// Creates a new `CodeTree` from its inner representation without validation.
    ///
    /// # Warning
    ///
    /// Assumes the provided SMT upholds the guarantees of the [`CodeTree`], i.e. every value
    /// marks its procedure root as present.
    pub fn new_unchecked(backend: Backend) -> Self {
        CodeTree { smt: backend }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the code SMT.
    pub fn root(&self) -> Word {
        self.smt.root()
    }

    /// Returns the number of procedure roots in this tree.
    pub fn num_procedures(&self) -> usize {
        self.smt.num_entries()
    }

    /// Returns an iterator over the procedure roots in the tree.
    pub fn procedure_roots(&self) -> impl Iterator<Item = ProcedureRoot> {
        self.smt.entries().map(|(key, _)| ProcedureRoot::from_raw(key))
    }

    /// Returns `true` if the procedure root is present in the tree, `false` otherwise.
    pub fn contains(&self, procedure_root: &ProcedureRoot) -> bool {
        self.smt.get_value(&procedure_root.as_word()) == PRESENT_VALUE
    }

    /// Returns a [`CodeWitness`] that proves the presence or absence of the procedure root.
    pub fn open(&self, procedure_root: &ProcedureRoot) -> CodeWitness {
        CodeWitness::new(self.smt.open(&procedure_root.as_word()))
    }
}

impl<Backend> CodeTree<Backend>
where
    Backend: SmtBackend<Error = MerkleError>,
{
    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Computes a mutation set resulting from inserting the provided procedure roots into this
    /// code tree.
    ///
    /// Procedure roots that are already present and duplicates are skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a leaf would exceed the maximum number of entries.
    pub fn compute_mutations(
        &self,
        procedure_roots: impl IntoIterator<Item = ProcedureRoot>,
    ) -> Result<CodeMutationSet, CodeTreeError> {
        // Collect all unique roots.
        let absent_roots: BTreeSet<ProcedureRoot> = procedure_roots
            .into_iter()
            .filter(|procedure_root| !self.contains(procedure_root))
            .collect();

        let mutation_set = self
            .smt
            .compute_mutations(
                absent_roots.into_iter().map(|root| (root.as_word(), PRESENT_VALUE)).collect(),
            )
            .map_err(CodeTreeError::ComputeMutations)?;

        Ok(CodeMutationSet::new(mutation_set))
    }

    /// Inserts the procedure root into the tree if it is absent.
    ///
    /// Returns `true` if the procedure root was newly inserted, `false` if it was already present.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the leaf of the procedure root would exceed the maximum number of entries.
    pub fn insert(&mut self, procedure_root: ProcedureRoot) -> Result<bool, CodeTreeError> {
        let prev_value = self
            .smt
            .insert(procedure_root.as_word(), PRESENT_VALUE)
            .map_err(CodeTreeError::MaxLeafEntriesExceeded)?;

        Ok(prev_value.is_empty())
    }

    /// Applies mutations to the code tree.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `mutations` was computed on a tree with a different root than this one.
    pub fn apply_mutations(&mut self, mutations: CodeMutationSet) -> Result<(), CodeTreeError> {
        self.smt
            .apply_mutations(mutations.into_mutation_set())
            .map_err(CodeTreeError::TreeRootConflict)
    }
}

impl CodeTree<Smt> {
    /// Creates a new code tree from the provided procedure roots.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided procedure roots contain duplicates.
    pub fn with_entries(
        procedure_roots: impl IntoIterator<Item = ProcedureRoot>,
    ) -> Result<Self, CodeTreeError> {
        let leaves = procedure_roots
            .into_iter()
            .map(|procedure_root| (procedure_root.as_word(), PRESENT_VALUE));

        let smt = Smt::with_entries(leaves).map_err(CodeTreeError::DuplicateProcedureRoots)?;

        Ok(Self::new_unchecked(smt))
    }
}

#[cfg(feature = "std")]
impl<Backend> CodeTree<LargeSmt<Backend>>
where
    Backend: SmtStorage,
{
    /// Creates a new code tree from the provided procedure roots using the given storage backend.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided procedure roots contain duplicates.
    pub fn with_storage_from_entries(
        storage: Backend,
        procedure_roots: impl IntoIterator<Item = ProcedureRoot>,
    ) -> Result<Self, CodeTreeError> {
        use crate::block::smt_backend::large_smt_error_to_merkle_error;

        let leaves = procedure_roots
            .into_iter()
            .map(|procedure_root| (procedure_root.as_word(), PRESENT_VALUE));

        let smt = LargeSmt::<Backend>::with_entries(storage, leaves)
            .map_err(large_smt_error_to_merkle_error)
            .map_err(CodeTreeError::DuplicateProcedureRoots)?;

        Ok(Self::new_unchecked(smt))
    }

    /// Returns a read-only code tree backed by a reader view of this tree's storage.
    ///
    /// The returned tree shares the same root and entries as `self`, but its storage is a
    /// read-only snapshot produced by [`SmtStorage::reader`]. The returned tree cannot be
    /// mutated.
    pub fn reader(&self) -> Result<CodeTree<LargeSmt<Backend::Reader>>, LargeSmtError> {
        Ok(CodeTree::new_unchecked(self.smt.reader()?))
    }
}

// CODE MUTATION SET
// ================================================================================================

/// A newtype wrapper around a [`MutationSet`] for use in the [`CodeTree`].
///
/// It guarantees that applying the contained mutations only inserts procedure roots, so that the
/// code tree stays append-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMutationSet {
    mutation_set: MutationSet<SMT_DEPTH, Word, Word>,
}

impl CodeMutationSet {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`CodeMutationSet`] from the provided raw mutation set.
    fn new(mutation_set: MutationSet<SMT_DEPTH, Word, Word>) -> Self {
        Self { mutation_set }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the underlying [`MutationSet`].
    pub fn as_mutation_set(&self) -> &MutationSet<SMT_DEPTH, Word, Word> {
        &self.mutation_set
    }

    // PUBLIC MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Consumes self and returns the underlying [`MutationSet`].
    pub fn into_mutation_set(self) -> MutationSet<SMT_DEPTH, Word, Word> {
        self.mutation_set
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::EMPTY_WORD;

    /// Returns two distinct procedure roots that map to the same leaf.
    pub(super) fn colliding_procedure_roots() -> [ProcedureRoot; 2] {
        [
            ProcedureRoot::from_raw(Word::from([1, 0, 0, 1000u32])),
            ProcedureRoot::from_raw(Word::from([2, 0, 0, 1000u32])),
        ]
    }

    #[test]
    fn apply_mutations_skips_present_and_duplicate_roots() -> anyhow::Result<()> {
        let proc0 = ProcedureRoot::mock(0);
        let proc1 = ProcedureRoot::mock(1);
        let proc2 = ProcedureRoot::mock(2);

        let mut tree = CodeTree::with_entries([proc0])?;
        let mutations = tree.compute_mutations([proc0, proc1, proc2, proc1])?;
        tree.apply_mutations(mutations)?;

        let expected = CodeTree::with_entries([proc0, proc1, proc2])?;
        assert_eq!(tree.root(), expected.root());
        assert_eq!(
            tree.procedure_roots().collect::<BTreeSet<_>>(),
            BTreeSet::from([proc0, proc1, proc2])
        );

        Ok(())
    }

    #[test]
    fn with_entries_rejects_duplicates() {
        let proc0 = ProcedureRoot::mock(0);
        let error = CodeTree::with_entries([proc0, proc0]).unwrap_err();
        assert_matches!(error, CodeTreeError::DuplicateProcedureRoots(_));
    }

    #[test]
    fn new_rejects_invalid_value() -> anyhow::Result<()> {
        let proc0 = ProcedureRoot::mock(0);
        let invalid_value = Word::from([2, 0, 0, 0u32]);
        let smt = Smt::with_entries([(proc0.as_word(), invalid_value)])?;

        let error = CodeTree::new(smt).unwrap_err();
        assert_matches!(
            error,
            CodeTreeError::InvalidLeafValue { procedure_root, value }
                if procedure_root == proc0 && value == invalid_value
        );

        Ok(())
    }

    #[test]
    fn colliding_procedure_roots_share_a_leaf() -> anyhow::Result<()> {
        let [collision0, collision1] = colliding_procedure_roots();
        let mut tree = CodeTree::with_entries([collision0])?;

        let absent_witness = tree.open(&collision1);
        assert_eq!(absent_witness.proof().get(&collision1.as_word()), Some(EMPTY_WORD));
        assert_eq!(absent_witness.proof().leaf().num_entries(), 1);

        assert!(tree.insert(collision1)?);

        for root in [collision0, collision1] {
            let witness = tree.open(&root);
            assert_eq!(witness.proof().get(&root.as_word()), Some(PRESENT_VALUE));
            assert_eq!(witness.proof().leaf().num_entries(), 2);
            assert_eq!(witness.proof().compute_root(), tree.root());
        }

        Ok(())
    }

    #[cfg(feature = "std")]
    #[test]
    fn large_smt_backend_same_root_as_regular_smt() -> anyhow::Result<()> {
        use miden_crypto::merkle::smt::MemoryStorage;

        let [collision0, collision1] = colliding_procedure_roots();
        let proc0 = ProcedureRoot::mock(0);
        let proc1 = ProcedureRoot::mock(1);

        let mut large_tree =
            CodeTree::with_storage_from_entries(MemoryStorage::default(), [proc0, collision0])?;
        let mut regular_tree = CodeTree::with_entries([proc0, collision0])?;
        assert_eq!(large_tree.root(), regular_tree.root());

        let mutations = large_tree.compute_mutations([proc0, proc1])?;
        large_tree.apply_mutations(mutations)?;
        assert!(large_tree.insert(collision1)?);

        regular_tree.insert(proc1)?;
        regular_tree.insert(collision1)?;

        assert_eq!(large_tree.root(), regular_tree.root());
        assert_eq!(
            large_tree.procedure_roots().collect::<BTreeSet<_>>(),
            regular_tree.procedure_roots().collect::<BTreeSet<_>>()
        );

        let reader = large_tree.reader()?;
        assert_eq!(reader.root(), regular_tree.root());
        assert_eq!(reader.open(&collision1), regular_tree.open(&collision1));

        Ok(())
    }
}
