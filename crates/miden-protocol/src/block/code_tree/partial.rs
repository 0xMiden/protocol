use super::{CodeTreeRoot, CodeWitness, PRESENT_VALUE};
use crate::code::ProcedureRoot;
use crate::crypto::merkle::smt::PartialSmt;
use crate::errors::CodeTreeError;

// PARTIAL CODE TREE
// ================================================================================================

/// The partial version of the [`CodeTree`](super::CodeTree).
///
/// It allows computing updates to the code tree without the full tree, e.g. during block
/// construction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartialCodeTree(PartialSmt);

impl PartialCodeTree {
    /// Creates a new partial code tree with the provided root that does not track any procedure
    /// roots.
    pub fn new(root: CodeTreeRoot) -> Self {
        PartialCodeTree(PartialSmt::new(root.as_word()))
    }

    /// Returns a new [`PartialCodeTree`] instantiated with the provided witnesses.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the merkle paths of the witnesses do not result in the same tree root.
    pub fn with_witnesses(
        witnesses: impl IntoIterator<Item = CodeWitness>,
    ) -> Result<Self, CodeTreeError> {
        PartialSmt::from_proofs(witnesses.into_iter().map(CodeWitness::into_proof))
            .map_err(CodeTreeError::TreeRootConflict)
            .map(Self)
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> CodeTreeRoot {
        CodeTreeRoot::from_raw(self.0.root())
    }

    /// Returns `true` if the procedure root is present in the tree, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the procedure root is not tracked by this partial code tree.
    pub fn contains(&self, procedure_root: &ProcedureRoot) -> Result<bool, CodeTreeError> {
        self.0
            .get_value(&procedure_root.as_word())
            .map(|value| value == PRESENT_VALUE)
            .map_err(|source| CodeTreeError::UntrackedProcedure {
                procedure_root: *procedure_root,
                source,
            })
    }

    /// Adds the given code witness to the partial tree and tracks it.
    ///
    /// Once a procedure root is tracked, it can be mutated using [`Self::insert`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - after the witness' merkle path was added, the partial code tree has a different root than
    ///   before it was added.
    pub fn track_procedure(&mut self, witness: CodeWitness) -> Result<(), CodeTreeError> {
        self.0.add_proof(witness.into_proof()).map_err(CodeTreeError::TreeRootConflict)
    }

    /// Inserts the procedure root into the tree if it is absent.
    ///
    /// Returns `true` if the procedure root was newly inserted, `false` if it was already present.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the procedure root is not tracked by this partial code tree, that is, its [`CodeWitness`]
    ///   was not added to the tree previously.
    /// - the leaf of the procedure root would exceed the maximum number of entries.
    pub fn insert(&mut self, procedure_root: ProcedureRoot) -> Result<bool, CodeTreeError> {
        if self.contains(&procedure_root)? {
            return Ok(false);
        }

        self.0
            .insert(procedure_root.as_word(), PRESENT_VALUE)
            .map_err(CodeTreeError::MaxLeafEntriesExceeded)?;

        Ok(true)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::block::code_tree::CodeTree;
    use crate::block::code_tree::tests::colliding_procedure_roots;

    #[test]
    fn partial_code_tree_root_mismatch() -> anyhow::Result<()> {
        let proc0 = ProcedureRoot::mock(0);
        let root1 = ProcedureRoot::mock(1);

        let mut tree = CodeTree::with_entries([proc0])?;
        let stale_witness = tree.open(&proc0);
        tree.insert(root1)?;
        let current_witness = tree.open(&root1);

        let mut partial = PartialCodeTree::with_witnesses([stale_witness])?;
        let error = partial.track_procedure(current_witness).unwrap_err();

        assert_matches!(error, CodeTreeError::TreeRootConflict(_));
        Ok(())
    }

    #[test]
    fn untracked_procedure() -> anyhow::Result<()> {
        let proc0 = ProcedureRoot::mock(0);
        let root1 = ProcedureRoot::mock(1);

        // The leaf of root1 must be non-empty, otherwise the partial tree can deduce its value from
        // the empty sibling of proc0's path.
        let tree = CodeTree::with_entries([proc0, root1])?;
        let mut partial = PartialCodeTree::with_witnesses([tree.open(&proc0)])?;

        let error = partial.insert(root1).unwrap_err();
        assert_matches!(error, CodeTreeError::UntrackedProcedure { procedure_root, .. } if procedure_root == root1);

        let error = partial.contains(&root1).unwrap_err();
        assert_matches!(error, CodeTreeError::UntrackedProcedure { procedure_root, .. } if procedure_root == root1);
        Ok(())
    }

    #[test]
    fn full_and_partial_code_tree_consistency() -> anyhow::Result<()> {
        let [collision0, collision1] = colliding_procedure_roots();
        let proc0 = ProcedureRoot::mock(0);
        let proc1 = ProcedureRoot::mock(1);
        let new_procs = [ProcedureRoot::mock(2), collision1];

        let mut tree = CodeTree::with_entries([proc0, proc1, collision0])?;
        let mut partial = PartialCodeTree::new(tree.root());

        for root in [proc0, proc1].into_iter().chain(new_procs) {
            partial.track_procedure(tree.open(&root))?;
        }
        assert_eq!(tree.root(), partial.root());

        // Inserting present roots is a no-op.
        assert!(!partial.insert(proc0)?);
        assert!(!partial.insert(proc1)?);
        assert_eq!(tree.root(), partial.root());

        for root in new_procs {
            assert!(!partial.contains(&root)?);
            assert!(tree.insert(root)?);
            assert!(partial.insert(root)?);
            assert!(partial.contains(&root)?);
        }
        assert_eq!(tree.root(), partial.root());

        Ok(())
    }
}
