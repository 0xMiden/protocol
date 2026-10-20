use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_core::mast::MastNodeExt;

use crate::code::ProcedureRoot;
use crate::crypto::SequentialCommit;
use crate::errors::CodeTreePatchError;
use crate::{Felt, Hasher, MastForest, ProtocolDomainRegistry, Word};

// CODE TREE PATCH
// ================================================================================================

/// The procedures a transaction creates, i.e. the code it adds to the
/// [`CodeTree`](super::CodeTree) and its code registry.
///
/// The created procedures are kept in the order in which the transaction kernel commits to them
/// and may contain duplicates. As a set, they are equal to the procedure roots of the contained
/// [`MastForest`]. The advice map of the forest is retained, since code may rely on it.
///
/// Each advice map key must be the hash of its value. The registry merges the advice maps of all
/// patches, so two entries with the same key must have the same value. Otherwise, a user could
/// register a key with an arbitrary value first and block all later code that uses the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeTreePatch {
    created_procedures: Vec<ProcedureRoot>,
    mast: Arc<MastForest>,
    commitment: Word,
}

impl CodeTreePatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum size of a serialized patch in bytes (256 KiB).
    pub const MAX_SIZE: u32 = 2u32.pow(18);

    /// Domain separator for the patch commitment.
    const DOMAIN: Felt = ProtocolDomainRegistry::CodeTreePatch.as_felt();

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`CodeTreePatch`] from the created procedures and the MAST forest that
    /// contains them.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a created procedure is not a procedure root of the forest.
    /// - a procedure root of the forest is not a created procedure.
    /// - a procedure root of the forest is a single external node, since it would register a
    ///   reference instead of code.
    /// - the serialized forest exceeds [`Self::MAX_SIZE`].
    /// - an advice map key is not the hash of its value.
    pub fn new(
        created_procedures: Vec<ProcedureRoot>,
        mast: Arc<MastForest>,
    ) -> Result<Self, CodeTreePatchError> {
        let forest_roots: BTreeSet<ProcedureRoot> =
            mast.procedure_digests().map(ProcedureRoot::from_raw).collect();
        let unique_created_procedures: BTreeSet<ProcedureRoot> =
            created_procedures.iter().copied().collect();

        if let Some(unknown_procedure) = unique_created_procedures.difference(&forest_roots).next()
        {
            return Err(CodeTreePatchError::CreatedProcedureNotInMastForest(*unknown_procedure));
        }

        if let Some(missing_procedure) = forest_roots.difference(&unique_created_procedures).next()
        {
            return Err(CodeTreePatchError::MastForestRootNotCreated(*missing_procedure));
        }

        if let Some(external_root) =
            mast.procedure_roots().iter().find(|root_id| mast[**root_id].is_external())
        {
            return Err(CodeTreePatchError::ExternalProcedureRoot(ProcedureRoot::from_raw(
                mast[*external_root].digest(),
            )));
        }

        // TODO: replace the temporary serialization with a size-hint API on MastForest once it
        // becomes available.
        let mut serialized_mast = Vec::new();
        mast.write_hashless(&mut serialized_mast);
        if serialized_mast.len() > Self::MAX_SIZE as usize {
            return Err(CodeTreePatchError::SizeLimitExceeded { size: serialized_mast.len() });
        }

        if let Some((key, _)) = mast
            .advice_map()
            .iter()
            .find(|(key, value)| Hasher::hash_elements(value) != **key)
        {
            return Err(CodeTreePatchError::AdviceMapKeyNotValueHash(*key));
        }

        Ok(Self::new_unchecked(created_procedures, mast))
    }

    /// Creates a new [`CodeTreePatch`] from its parts without validation.
    fn new_unchecked(created_procedures: Vec<ProcedureRoot>, mast: Arc<MastForest>) -> Self {
        let commitment = if is_empty_patch(&created_procedures, &mast) {
            Word::empty()
        } else {
            Hasher::hash_elements_in_domain(
                &commitment_elements(&created_procedures, &mast),
                Self::DOMAIN,
            )
        };

        Self { created_procedures, mast, commitment }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the MAST forest containing the created procedures.
    pub fn mast(&self) -> &Arc<MastForest> {
        &self.mast
    }

    /// Returns an iterator over the created procedure roots in kernel order, including
    /// duplicates.
    pub fn created_procedures(&self) -> impl Iterator<Item = ProcedureRoot> + '_ {
        self.created_procedures.iter().copied()
    }

    /// Returns `true` if the patch creates no procedures and has an empty advice map.
    pub fn is_empty(&self) -> bool {
        is_empty_patch(&self.created_procedures, &self.mast)
    }

    /// Returns the elements the commitment to this patch is computed from.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }

    /// Returns the commitment to this patch.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }
}

impl Default for CodeTreePatch {
    fn default() -> Self {
        Self::new_unchecked(Vec::new(), Arc::new(MastForest::new()))
    }
}

impl SequentialCommit for CodeTreePatch {
    type Commitment = Word;

    /// Returns the created procedure roots in kernel order, followed by the advice map
    /// commitment of the MAST forest.
    ///
    /// For an empty patch, an empty vector is returned.
    fn to_elements(&self) -> Vec<Felt> {
        if self.is_empty() {
            return Vec::new();
        }

        commitment_elements(&self.created_procedures, &self.mast)
    }

    /// Returns the commitment to this patch, or [`Word::empty`] for an empty patch.
    fn to_commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

// HELPERS
// ================================================================================================

/// Returns `true` if there are no created procedures and the advice map is empty.
fn is_empty_patch(created_procedures: &[ProcedureRoot], mast: &MastForest) -> bool {
    created_procedures.is_empty() && mast.advice_map().is_empty()
}

/// Returns the created procedure roots followed by the advice map commitment of the forest.
fn commitment_elements(created_procedures: &[ProcedureRoot], mast: &MastForest) -> Vec<Felt> {
    let mut elements = Vec::with_capacity((created_procedures.len() + 1) * Word::NUM_ELEMENTS);
    for procedure_root in created_procedures {
        elements.extend_from_slice(procedure_root.as_elements());
    }
    elements.extend_from_slice(mast.advice_commitment().as_elements());

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

    const LIBRARY_SOURCE: &str = "
        pub proc foo
            push.1 drop
        end

        pub proc bar
            push.2 drop
        end
    ";

    fn library_forest() -> Arc<MastForest> {
        assemble_test_package("test-code-tree-patch", "test::code_tree_patch", LIBRARY_SOURCE)
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
        let patch = CodeTreePatch::new(Vec::new(), Arc::new(MastForest::new()))?;

        assert!(patch.is_empty());
        assert!(patch.to_elements().is_empty());
        assert_eq!(patch.to_commitment(), Word::empty());
        assert_eq!(patch, CodeTreePatch::default());

        Ok(())
    }

    #[test]
    fn commitment_covers_created_procedures_in_order_and_advice_map() -> anyhow::Result<()> {
        let mast = library_forest();
        let mast = Arc::new((*mast).clone().with_advice_map(advice_map_with_value_len(4)));
        let [proc0, proc1] = <[ProcedureRoot; 2]>::try_from(forest_roots(&mast))
            .map_err(|roots| anyhow::anyhow!("expected two forest roots, got {}", roots.len()))?;

        // Unsorted kernel order with a duplicate.
        let created_procedures = vec![proc1, proc0, proc1];
        let patch = CodeTreePatch::new(created_procedures.clone(), mast.clone())?;

        let mut expected_elements: Vec<Felt> =
            created_procedures.iter().flat_map(|root| root.as_elements().to_vec()).collect();
        expected_elements.extend_from_slice(mast.advice_commitment().as_elements());

        assert!(!patch.is_empty());
        assert_eq!(patch.created_procedures().collect::<Vec<_>>(), created_procedures);
        assert_eq!(patch.to_elements(), expected_elements);
        assert_eq!(
            patch.to_commitment(),
            Hasher::hash_elements_in_domain(&expected_elements, CodeTreePatch::DOMAIN)
        );

        Ok(())
    }

    #[test]
    fn advice_map_without_procedures_is_allowed() -> anyhow::Result<()> {
        let mast = MastForest::new().with_advice_map(advice_map_with_value_len(4));
        let advice_commitment = mast.advice_commitment();
        let patch = CodeTreePatch::new(Vec::new(), Arc::new(mast))?;

        assert!(!patch.is_empty());
        assert_eq!(patch.created_procedures().count(), 0);
        assert_eq!(patch.to_elements(), advice_commitment.as_elements());
        assert_eq!(
            patch.to_commitment(),
            Hasher::hash_elements_in_domain(advice_commitment.as_elements(), CodeTreePatch::DOMAIN)
        );

        Ok(())
    }

    #[test]
    fn new_rejects_created_procedure_not_in_forest() {
        let unknown_procedure = ProcedureRoot::mock(0);
        let mast = library_forest();
        let mut created_procedures = forest_roots(&mast);
        created_procedures.push(unknown_procedure);

        let error = CodeTreePatch::new(created_procedures, mast).unwrap_err();
        assert_matches!(
            error,
            CodeTreePatchError::CreatedProcedureNotInMastForest(root) if root == unknown_procedure
        );
    }

    #[test]
    fn new_rejects_forest_root_that_is_not_created() {
        let mast = library_forest();
        let mut created_procedures = forest_roots(&mast);
        let missing_procedure = created_procedures.pop().expect("forest should have roots");

        let error = CodeTreePatch::new(created_procedures, mast).unwrap_err();
        assert_matches!(
            error,
            CodeTreePatchError::MastForestRootNotCreated(root) if root == missing_procedure
        );
    }

    #[test]
    fn new_rejects_external_procedure_root() {
        let external_digest = Word::from([5, 6, 7, 8u32]);
        let (mast, _) = create_external_node_forest(external_digest);
        let external_root = ProcedureRoot::from_raw(external_digest);

        let error = CodeTreePatch::new(vec![external_root], Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodeTreePatchError::ExternalProcedureRoot(root) if root == external_root
        );
    }

    #[test]
    fn new_rejects_advice_map_key_that_is_not_value_hash() {
        let invalid_key = Word::from([1, 2, 3, 4u32]);
        let mut advice_map = AdviceMap::default();
        advice_map.insert(invalid_key, vec![Felt::ONE]);
        let mast = MastForest::new().with_advice_map(advice_map);

        let error = CodeTreePatch::new(Vec::new(), Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodeTreePatchError::AdviceMapKeyNotValueHash(key) if key == invalid_key
        );
    }

    #[test]
    fn new_rejects_oversized_forest() {
        let value_len = CodeTreePatch::MAX_SIZE as usize / size_of::<u64>();
        let mast = MastForest::new().with_advice_map(advice_map_with_value_len(value_len));

        let error = CodeTreePatch::new(Vec::new(), Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodeTreePatchError::SizeLimitExceeded { size } if size > CodeTreePatch::MAX_SIZE as usize
        );
    }
}
