use alloc::vec::Vec;

use crate::code::ProcedureRoot;
use crate::crypto::SequentialCommit;
use crate::{Felt, Hasher, ProtocolDomainRegistry, Word};

// CODE TREE DEPENDENCIES
// ================================================================================================

/// The procedures that the public code of a transaction depends on and that the transaction
/// proves present in the [`CodeTree`](super::CodeTree).
///
/// Besides the procedures that the external nodes of a [`CodeTreePatch`](super::CodeTreePatch)
/// reference and that the transaction does not create, it contains top-level roots that are
/// already present, e.g. a note script root.
///
/// The dependencies are in the order in which the transaction kernel commits to them and may
/// contain duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeTreeDependencies {
    dependencies: Vec<ProcedureRoot>,
    commitment: Word,
}

impl CodeTreeDependencies {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Domain separator for the dependencies commitment.
    const DOMAIN: Felt = ProtocolDomainRegistry::CodeTreeDependencies.as_felt();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`CodeTreeDependencies`] from the procedure roots in kernel order.
    pub fn new(dependencies: Vec<ProcedureRoot>) -> Self {
        let commitment = if dependencies.is_empty() {
            Word::empty()
        } else {
            Hasher::hash_elements_in_domain(&commitment_elements(&dependencies), Self::DOMAIN)
        };

        Self { dependencies, commitment }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the dependencies in kernel order, including duplicates.
    pub fn iter(&self) -> impl Iterator<Item = ProcedureRoot> + '_ {
        self.dependencies.iter().copied()
    }

    /// Returns the number of dependencies, including duplicates.
    pub fn num_dependencies(&self) -> usize {
        self.dependencies.len()
    }

    /// Returns `true` if there are no dependencies.
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
    }

    /// Returns `true` if the procedure root is a dependency.
    pub fn contains(&self, procedure_root: &ProcedureRoot) -> bool {
        self.dependencies.contains(procedure_root)
    }

    /// Returns the elements the commitment to the dependencies is computed from.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns the commitment to the dependencies.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl SequentialCommit for CodeTreeDependencies {
    type Commitment = Word;

    /// Returns the dependencies in kernel order.
    fn to_elements(&self) -> Vec<Felt> {
        commitment_elements(&self.dependencies)
    }

    /// Returns the commitment to the dependencies, or [`Word::empty`] if there are none.
    fn to_commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

// HELPERS
// ================================================================================================

/// Returns the procedure roots as a sequence of field elements.
fn commitment_elements(dependencies: &[ProcedureRoot]) -> Vec<Felt> {
    let mut elements = Vec::with_capacity(dependencies.len() * Word::NUM_ELEMENTS);
    for dependency in dependencies {
        elements.extend_from_slice(dependency.as_elements());
    }

    elements
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn empty_dependencies_have_empty_commitment() {
        let dependencies = CodeTreeDependencies::new(Vec::new());

        assert!(dependencies.is_empty());
        assert_eq!(dependencies.num_dependencies(), 0);
        assert!(dependencies.to_elements().is_empty());
        assert_eq!(dependencies.to_commitment(), Word::empty());
        assert_eq!(dependencies, CodeTreeDependencies::default());
    }

    #[test]
    fn non_empty_dependencies() {
        let proc0 = ProcedureRoot::mock(0);
        let proc1 = ProcedureRoot::mock(1);

        // Unsorted kernel order with a duplicate.
        let roots = vec![proc1, proc0, proc1];
        let dependencies = CodeTreeDependencies::new(roots.clone());

        assert_eq!(dependencies.num_dependencies(), 3);
        assert!(dependencies.contains(&proc0));
        assert_eq!(dependencies.iter().collect::<Vec<_>>(), roots);
    }
}
