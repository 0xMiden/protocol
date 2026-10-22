use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_core::mast::MastNodeExt;

use crate::code::ProcedureRoot;
use crate::errors::CodePatchError;
use crate::{Felt, Hasher, MastForest, ProtocolDomainRegistry, Word};

// CODE PATCH
// ================================================================================================

/// The procedures a transaction creates, i.e. the code it adds to the
/// [`CodeTree`](super::CodeTree) and its code registry, and the procedures it depends on.
///
/// The created procedures are equal to the procedure roots of the contained [`MastForest`]. They
/// are retained separately to keep tx kernel emission order. The advice map of the forest is
/// retained, since code may rely on it.
///
/// The dependencies are the procedures that the external nodes of the forest reference and that
/// the transaction proves present in the code tree. The host selects them, so they are committed
/// to and must match the external nodes exactly. This rejects missing dependencies and extra ones,
/// which would only add cost. A top-level root that is already present, e.g. a note script root,
/// is not a dependency, since the transaction kernel selects it and the transaction proof already
/// attests to its presence.
///
/// A dependency must not be a created procedure, i.e. an external node must not reference a
/// created procedure. Building the forest with [`MastForest::merge`] replaces such references with
/// the procedure itself. This prevents a host from moving an inner node of a created procedure
/// into a separate created procedure, which would add a code tree entry. It also rejects a
/// procedure root that is a single external node, which would register a reference instead of
/// code.
///
/// Both lists are kept in the order in which the transaction kernel commits to them.
///
/// The commitment to created procedures and advice ([`Self::created_commitment`]) is the sequential
/// hash of:
/// ```text
/// [CREATED_PROC_ROOT_0, ..., CREATED_PROC_ROOT_N, ADVICE_COMMITMENT].
/// ```
///
/// The commitment to dependencies ([`Self::dependencies_commitment`]) is the sequential hash of:
/// ```text
/// [DEPENDENCY_PROC_ROOT_0, ..., DEPENDENCY_PROC_ROOT_N].
/// ```
///
/// The commitment to the patch ([`Self::commitment`]) is the hash of:
/// ```text
/// [CREATED_COMMITMENT, DEPENDENCIES_COMMITMENT].
/// ```
///
/// Each advice map key must be the hash of its value. The registry merges the advice maps of all
/// patches, so two entries with the same key must have the same value. Otherwise, a user could
/// register a key with an arbitrary value first and block all later code that uses the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodePatch {
    created_procedures: Vec<ProcedureRoot>,
    dependencies: Vec<ProcedureRoot>,
    mast: Arc<MastForest>,

    created_commitment: Word,
    dependencies_commitment: Word,
    commitment: Word,
}

impl CodePatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum size of a serialized patch in bytes (256 KiB).
    pub const MAX_SIZE: u32 = 2u32.pow(18);

    /// Domain separator for the patch commitment.
    const DOMAIN: Felt = ProtocolDomainRegistry::CodePatch.as_felt();

    /// Domain separator for the created procedures commitment.
    const CREATED_DOMAIN: Felt = ProtocolDomainRegistry::CodePatchCreated.as_felt();

    /// Domain separator for the dependencies commitment.
    const DEPENDENCIES_DOMAIN: Felt = ProtocolDomainRegistry::CodePatchDependencies.as_felt();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`CodePatch`] from the created procedures, the dependencies and the MAST
    /// forest that contains them.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a created procedure or a dependency is duplicated.
    /// - a dependency is also a created procedure.
    /// - a created procedure is not a procedure root of the forest.
    /// - a procedure root of the forest is not a created procedure.
    /// - an external node of the forest does not reference a dependency.
    /// - a dependency is not referenced by an external node of the forest.
    /// - the serialized forest exceeds [`Self::MAX_SIZE`].
    /// - an advice map key is not the hash of its value.
    pub fn new(
        created_procedures: Vec<ProcedureRoot>,
        dependencies: Vec<ProcedureRoot>,
        mast: Arc<MastForest>,
    ) -> Result<Self, CodePatchError> {
        let unique_created_procedures = unique_procedure_roots(&created_procedures)
            .map_err(CodePatchError::DuplicateCreatedProcedure)?;
        let unique_dependencies =
            unique_procedure_roots(&dependencies).map_err(CodePatchError::DuplicateDependency)?;

        if let Some(created_dependency) =
            unique_created_procedures.intersection(&unique_dependencies).next()
        {
            return Err(CodePatchError::DependencyIsCreatedProcedure(*created_dependency));
        }

        let forest_roots: BTreeSet<ProcedureRoot> =
            mast.procedure_digests().map(ProcedureRoot::from_raw).collect();

        if let Some(unknown_procedure) = unique_created_procedures.difference(&forest_roots).next()
        {
            return Err(CodePatchError::CreatedProcedureNotInMastForest(*unknown_procedure));
        }

        if let Some(missing_procedure) = forest_roots.difference(&unique_created_procedures).next()
        {
            return Err(CodePatchError::MastForestRootNotCreated(*missing_procedure));
        }

        let external_references: BTreeSet<ProcedureRoot> = mast
            .nodes()
            .iter()
            .filter(|node| node.is_external())
            .map(|node| ProcedureRoot::from_raw(node.digest()))
            .collect();

        if let Some(undeclared_reference) =
            external_references.difference(&unique_dependencies).next()
        {
            return Err(CodePatchError::ExternalNodeNotDependency(*undeclared_reference));
        }

        if let Some(unreferenced_dependency) =
            unique_dependencies.difference(&external_references).next()
        {
            return Err(CodePatchError::DependencyNotExternalNode(*unreferenced_dependency));
        }

        // TODO: replace the temporary serialization with a size-hint API on MastForest once it
        // becomes available.
        let mut serialized_mast = Vec::new();
        mast.write_hashless(&mut serialized_mast);
        if serialized_mast.len() > Self::MAX_SIZE as usize {
            return Err(CodePatchError::SizeLimitExceeded { size: serialized_mast.len() });
        }

        // Ensure all advice map keys are the sequential hashes of their values.
        if let Some((key, _)) = mast
            .advice_map()
            .iter()
            .find(|(key, value)| Hasher::hash_elements(value) != **key)
        {
            return Err(CodePatchError::AdviceMapKeyNotValueHash(*key));
        }

        Ok(Self::new_unchecked(created_procedures, dependencies, mast))
    }

    /// Creates a new [`CodePatch`] from its parts without validation.
    fn new_unchecked(
        created_procedures: Vec<ProcedureRoot>,
        dependencies: Vec<ProcedureRoot>,
        mast: Arc<MastForest>,
    ) -> Self {
        let created_commitment = if is_empty_created(&created_procedures, &mast) {
            Word::empty()
        } else {
            Hasher::hash_elements_in_domain(
                &created_elements(&created_procedures, &mast),
                Self::CREATED_DOMAIN,
            )
        };

        let dependencies_commitment = if dependencies.is_empty() {
            Word::empty()
        } else {
            Hasher::hash_elements_in_domain(
                &procedure_root_elements(&dependencies),
                Self::DEPENDENCIES_DOMAIN,
            )
        };

        let commitment = if created_commitment.is_empty() && dependencies_commitment.is_empty() {
            Word::empty()
        } else {
            Hasher::merge_in_domain(&[created_commitment, dependencies_commitment], Self::DOMAIN)
        };

        Self {
            created_procedures,
            dependencies,
            mast,
            created_commitment,
            dependencies_commitment,
            commitment,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the MAST forest containing the created procedures.
    pub fn mast(&self) -> &Arc<MastForest> {
        &self.mast
    }

    /// Returns an iterator over the created procedure roots in kernel order.
    pub fn created_procedures(&self) -> impl Iterator<Item = ProcedureRoot> + '_ {
        self.created_procedures.iter().copied()
    }

    /// Returns an iterator over the dependencies in kernel order.
    pub fn dependencies(&self) -> impl Iterator<Item = ProcedureRoot> + '_ {
        self.dependencies.iter().copied()
    }

    /// Returns `true` if the patch creates no procedures, has no dependencies and has an empty
    /// advice map.
    pub fn is_empty(&self) -> bool {
        is_empty_created(&self.created_procedures, &self.mast) && self.dependencies.is_empty()
    }

    /// Returns the elements the created procedures commitment is computed from: the created
    /// procedure roots in kernel order, followed by the advice map commitment of the forest.
    ///
    /// If there are no created procedures and the advice map is empty, an empty vector is
    /// returned.
    pub fn to_created_elements(&self) -> Vec<Felt> {
        if is_empty_created(&self.created_procedures, &self.mast) {
            return Vec::new();
        }

        created_elements(&self.created_procedures, &self.mast)
    }

    /// Returns the elements the dependencies commitment is computed from: the dependencies in
    /// kernel order.
    pub fn to_dependencies_elements(&self) -> Vec<Felt> {
        procedure_root_elements(&self.dependencies)
    }

    /// Returns the commitment to the created procedures and the advice map, or [`Word::empty`]
    /// if both are empty.
    pub fn created_commitment(&self) -> Word {
        self.created_commitment
    }

    /// Returns the commitment to the dependencies, or [`Word::empty`] if there are none.
    pub fn dependencies_commitment(&self) -> Word {
        self.dependencies_commitment
    }

    /// Returns the commitment to this patch, or [`Word::empty`] for an empty patch.
    pub fn commitment(&self) -> Word {
        self.commitment
    }
}

impl Default for CodePatch {
    fn default() -> Self {
        Self::new_unchecked(Vec::new(), Vec::new(), Arc::new(MastForest::new()))
    }
}

// HELPERS
// ================================================================================================

/// Returns the set of procedure roots, or the first duplicated procedure root.
fn unique_procedure_roots(
    procedure_roots: &[ProcedureRoot],
) -> Result<BTreeSet<ProcedureRoot>, ProcedureRoot> {
    let mut unique_roots = BTreeSet::new();
    for procedure_root in procedure_roots {
        if !unique_roots.insert(*procedure_root) {
            return Err(*procedure_root);
        }
    }

    Ok(unique_roots)
}

/// Returns `true` if there are no created procedures and the advice map is empty.
fn is_empty_created(created_procedures: &[ProcedureRoot], mast: &MastForest) -> bool {
    created_procedures.is_empty() && mast.advice_map().is_empty()
}

/// Returns the created procedure roots followed by the advice map commitment of the forest.
fn created_elements(created_procedures: &[ProcedureRoot], mast: &MastForest) -> Vec<Felt> {
    let mut elements = procedure_root_elements(created_procedures);
    elements.extend_from_slice(mast.advice_commitment().as_elements());

    elements
}

/// Returns the procedure roots as a sequence of field elements.
fn procedure_root_elements(procedure_roots: &[ProcedureRoot]) -> Vec<Felt> {
    let mut elements = Vec::with_capacity((procedure_roots.len() + 1) * Word::NUM_ELEMENTS);
    for procedure_root in procedure_roots {
        elements.extend_from_slice(procedure_root.as_elements());
    }

    elements
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use assert_matches::assert_matches;

    use super::*;
    use crate::testing::assembler::assemble_test_package;
    use crate::utils::create_external_node_forest;
    use crate::vm::AdviceMap;

    /// The digest `[1, 2, 3, 4]` called by `bar`, which becomes an external node of the forest.
    const EXTERNAL_DIGEST: Word =
        Word::new([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)]);

    const LIBRARY_SOURCE: &str = "
        pub proc foo
            push.1 drop
        end

        pub proc bar
            call.0x0100000000000000020000000000000003000000000000000400000000000000
        end
    ";

    fn library_forest() -> Arc<MastForest> {
        assemble_test_package("test-code-patch", "test::code_patch", LIBRARY_SOURCE)
            .mast_forest()
            .clone()
    }

    /// Returns an advice map with a single entry whose key is the hash of its value.
    fn advice_map_with_value_len(value_len: usize) -> AdviceMap {
        let value = vec![Felt::ONE; value_len];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(Hasher::hash_elements(&value), value);
        advice_map
    }

    fn forest_roots(mast: &MastForest) -> Vec<ProcedureRoot> {
        mast.procedure_digests().map(ProcedureRoot::from_raw).collect()
    }

    #[test]
    fn empty_patch_has_empty_commitment() -> anyhow::Result<()> {
        let patch = CodePatch::new(Vec::new(), Vec::new(), Arc::new(MastForest::new()))?;

        assert!(patch.is_empty());
        assert!(patch.to_created_elements().is_empty());
        assert!(patch.to_dependencies_elements().is_empty());
        assert_eq!(patch.created_commitment(), Word::empty());
        assert_eq!(patch.dependencies_commitment(), Word::empty());
        assert_eq!(patch.commitment(), Word::empty());
        assert_eq!(patch, CodePatch::default());

        Ok(())
    }

    #[test]
    fn commitment_covers_created_procedures_dependencies_and_advice_map() -> anyhow::Result<()> {
        let mast = library_forest();
        let mast = Arc::new((*mast).clone().with_advice_map(advice_map_with_value_len(4)));
        let [proc0, proc1] = <[ProcedureRoot; 2]>::try_from(forest_roots(&mast))
            .map_err(|roots| anyhow::anyhow!("expected two forest roots, got {}", roots.len()))?;
        let external_procedure = ProcedureRoot::from_raw(EXTERNAL_DIGEST);

        // Unsorted kernel order.
        let created_procedures = vec![proc1, proc0];
        let dependencies = vec![external_procedure];
        let patch = CodePatch::new(created_procedures.clone(), dependencies.clone(), mast.clone())?;

        let mut expected_created_elements: Vec<Felt> =
            created_procedures.iter().flat_map(|root| root.as_elements().to_vec()).collect();
        expected_created_elements.extend_from_slice(mast.advice_commitment().as_elements());
        let expected_dependencies_elements: Vec<Felt> =
            dependencies.iter().flat_map(|root| root.as_elements().to_vec()).collect();
        let expected_created_commitment =
            Hasher::hash_elements_in_domain(&expected_created_elements, CodePatch::CREATED_DOMAIN);
        let expected_dependencies_commitment = Hasher::hash_elements_in_domain(
            &expected_dependencies_elements,
            CodePatch::DEPENDENCIES_DOMAIN,
        );

        assert!(!patch.is_empty());
        assert_eq!(patch.created_procedures().collect::<Vec<_>>(), created_procedures);
        assert_eq!(patch.dependencies().collect::<Vec<_>>(), dependencies);
        assert_eq!(patch.to_created_elements(), expected_created_elements);
        assert_eq!(patch.to_dependencies_elements(), expected_dependencies_elements);
        assert_eq!(patch.created_commitment(), expected_created_commitment);
        assert_eq!(patch.dependencies_commitment(), expected_dependencies_commitment);
        assert_eq!(
            patch.commitment(),
            Hasher::merge_in_domain(
                &[expected_created_commitment, expected_dependencies_commitment],
                CodePatch::DOMAIN
            )
        );

        Ok(())
    }

    #[test]
    fn advice_map_without_procedures_is_allowed() -> anyhow::Result<()> {
        let mast = MastForest::new().with_advice_map(advice_map_with_value_len(4));
        let advice_commitment = mast.advice_commitment();
        let patch = CodePatch::new(Vec::new(), Vec::new(), Arc::new(mast))?;
        let expected_created_commitment = Hasher::hash_elements_in_domain(
            advice_commitment.as_elements(),
            CodePatch::CREATED_DOMAIN,
        );

        assert!(!patch.is_empty());
        assert_eq!(patch.created_procedures().count(), 0);
        assert_eq!(patch.to_created_elements(), advice_commitment.as_elements());
        assert_eq!(patch.created_commitment(), expected_created_commitment);
        assert_eq!(patch.dependencies_commitment(), Word::empty());
        assert_eq!(
            patch.commitment(),
            Hasher::merge_in_domain(
                &[expected_created_commitment, Word::empty()],
                CodePatch::DOMAIN
            )
        );

        Ok(())
    }

    #[test]
    fn new_rejects_duplicate_created_procedure() {
        let mast = library_forest();
        let mut created_procedures = forest_roots(&mast);
        let duplicate_procedure = created_procedures[0];
        created_procedures.push(duplicate_procedure);

        let error = CodePatch::new(created_procedures, Vec::new(), mast).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::DuplicateCreatedProcedure(root) if root == duplicate_procedure
        );
    }

    #[test]
    fn new_rejects_duplicate_dependency() {
        let mast = library_forest();
        let external_procedure = ProcedureRoot::from_raw(EXTERNAL_DIGEST);
        let dependencies = vec![external_procedure, external_procedure];

        let error = CodePatch::new(forest_roots(&mast), dependencies, mast).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::DuplicateDependency(root) if root == external_procedure
        );
    }

    #[test]
    fn new_rejects_dependency_that_is_created_procedure() {
        let mast = library_forest();
        let created_procedures = forest_roots(&mast);
        let created_dependency = created_procedures[0];

        let error = CodePatch::new(created_procedures, vec![created_dependency], mast).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::DependencyIsCreatedProcedure(root) if root == created_dependency
        );
    }

    #[test]
    fn new_rejects_dependency_that_is_not_external_node() {
        let mast = library_forest();
        let unreferenced_dependency = ProcedureRoot::mock(0);
        let dependencies = vec![ProcedureRoot::from_raw(EXTERNAL_DIGEST), unreferenced_dependency];

        let error = CodePatch::new(forest_roots(&mast), dependencies, mast).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::DependencyNotExternalNode(root) if root == unreferenced_dependency
        );
    }

    #[test]
    fn new_rejects_external_node_that_is_not_dependency() {
        let mast = library_forest();
        let external_procedure = ProcedureRoot::from_raw(EXTERNAL_DIGEST);

        let error = CodePatch::new(forest_roots(&mast), Vec::new(), mast).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::ExternalNodeNotDependency(root) if root == external_procedure
        );
    }

    #[test]
    fn new_rejects_created_procedure_not_in_forest() {
        let unknown_procedure = ProcedureRoot::mock(0);
        let mast = library_forest();
        let mut created_procedures = forest_roots(&mast);
        created_procedures.push(unknown_procedure);

        let error = CodePatch::new(created_procedures, Vec::new(), mast).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::CreatedProcedureNotInMastForest(root) if root == unknown_procedure
        );
    }

    #[test]
    fn new_rejects_forest_root_that_is_not_created() {
        let mast = library_forest();
        let mut created_procedures = forest_roots(&mast);
        let missing_procedure = created_procedures.pop().expect("forest should have roots");

        let error = CodePatch::new(created_procedures, Vec::new(), mast).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::MastForestRootNotCreated(root) if root == missing_procedure
        );
    }

    #[test]
    fn new_rejects_external_procedure_root() {
        let external_digest = Word::from([5, 6, 7, 8u32]);
        let (mast, _) = create_external_node_forest(external_digest);
        let external_root = ProcedureRoot::from_raw(external_digest);

        let error = CodePatch::new(vec![external_root], Vec::new(), Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::ExternalNodeNotDependency(root) if root == external_root
        );
    }

    #[test]
    fn new_rejects_advice_map_key_that_is_not_value_hash() {
        let invalid_key = Word::from([1, 2, 3, 4u32]);
        let mut advice_map = AdviceMap::default();
        advice_map.insert(invalid_key, vec![Felt::ONE]);
        let mast = MastForest::new().with_advice_map(advice_map);

        let error = CodePatch::new(Vec::new(), Vec::new(), Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::AdviceMapKeyNotValueHash(key) if key == invalid_key
        );
    }

    #[test]
    fn new_rejects_oversized_forest() {
        let value_len = CodePatch::MAX_SIZE as usize / size_of::<u64>();
        let mast = MastForest::new().with_advice_map(advice_map_with_value_len(value_len));

        let error = CodePatch::new(Vec::new(), Vec::new(), Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::SizeLimitExceeded { size } if size > CodePatch::MAX_SIZE as usize
        );
    }
}
