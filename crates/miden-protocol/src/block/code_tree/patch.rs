use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_core::mast::MastNodeExt;
use miden_crypto::hash::eidos::domain::{EidosDomain, FeltSequence};

use crate::code::ProcedureRoot;
use crate::errors::CodePatchError;
use crate::{Hasher, MastForest, Word};

// CODE PATCH KIND
// ================================================================================================

/// The parameters of a level of code patches, e.g. the patches of transactions.
///
/// Each level has its own limits, because a merged patch contains the code of many patches, and
/// its own commitment domain, so that the commitments of different levels cannot be confused.
pub(crate) trait CodePatchKind {
    /// The domain of the commitment to the patch.
    type CommitmentDomain: EidosDomain<Encoding = FeltSequence>;

    /// The value of [`Self::CommitmentDomain`].
    const COMMITMENT_DOMAIN: Self::CommitmentDomain;

    /// The maximum size of a serialized patch in bytes.
    const MAX_SIZE: u32;

    /// The maximum number of procedure roots in each list of a patch.
    const MAX_ROOTS: usize;
}

// CODE PATCH
// ================================================================================================

/// The shared implementation of the code patches of all levels.
///
/// See [`TransactionCodePatch`](crate::transaction::TransactionCodePatch) for the invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodePatch<Kind> {
    mast: Arc<MastForest>,
    commitment: Word,
    kind: PhantomData<Kind>,
}

impl<Kind: CodePatchKind> CodePatch<Kind> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`CodePatch`] from the MAST forest of the created procedures.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the number of procedure roots or external nodes of the forest exceeds
    ///   [`CodePatchKind::MAX_ROOTS`].
    /// - a procedure root or an external node digest of the forest is duplicated.
    /// - an external node references a procedure root of the forest.
    /// - a node of the forest is not reachable from a procedure root.
    /// - the advice map of the forest is not empty.
    /// - the serialized forest exceeds [`CodePatchKind::MAX_SIZE`].
    pub(crate) fn new(mast: Arc<MastForest>) -> Result<Self, CodePatchError> {
        let num_created_procedures = mast.procedure_roots().len();
        if num_created_procedures > Kind::MAX_ROOTS {
            return Err(CodePatchError::TooManyCreatedProcedures {
                count: num_created_procedures,
                max: Kind::MAX_ROOTS,
            });
        }

        let num_dependencies = external_node_digests(&mast).count();
        if num_dependencies > Kind::MAX_ROOTS {
            return Err(CodePatchError::TooManyDependencies {
                count: num_dependencies,
                max: Kind::MAX_ROOTS,
            });
        }

        let created_procedures = unique_procedure_roots(mast.procedure_digests())
            .map_err(CodePatchError::DuplicateCreatedProcedure)?;
        let dependencies = unique_procedure_roots(external_node_digests(&mast))
            .map_err(CodePatchError::DuplicateDependency)?;

        if let Some(created_dependency) = created_procedures.intersection(&dependencies).next() {
            return Err(CodePatchError::DependencyIsCreatedProcedure(*created_dependency));
        }

        if let Some(unreachable_node) = find_unreachable_node(&mast) {
            return Err(CodePatchError::UnreachableMastNode(unreachable_node));
        }

        if !mast.advice_map().is_empty() {
            return Err(CodePatchError::AdviceMapNotEmpty);
        }

        // TODO: replace the temporary serialization with a size-hint API on MastForest once it
        // becomes available.
        let mut serialized_mast = Vec::new();
        mast.write_hashless(&mut serialized_mast);
        if serialized_mast.len() > Kind::MAX_SIZE as usize {
            return Err(CodePatchError::SizeLimitExceeded {
                size: serialized_mast.len(),
                max_size: Kind::MAX_SIZE,
            });
        }

        Ok(Self::new_unchecked(mast))
    }

    /// Merges the patches of a lower level into one patch, e.g. the patches of the transactions of
    /// a batch.
    ///
    /// The merge deduplicates code that more than one patch contains. A dependency of one patch is
    /// not a dependency of the merged patch if another patch contains its code, because
    /// [`MastForest::merge`] replaces the external node with this code. If the code is a created
    /// procedure, the patches prove against different code tree roots, and its insertion into the
    /// code tree is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the forests cannot be merged.
    /// - the merged forest is not a valid patch (see [`Self::new`]), e.g. because it exceeds the
    ///   limits or contains two procedures with equal digests that differ in their MAST.
    pub(crate) fn merge<'patch, PatchKind: CodePatchKind + 'patch>(
        patches: impl IntoIterator<Item = &'patch CodePatch<PatchKind>>,
    ) -> Result<Self, CodePatchError> {
        let (mast, _) = MastForest::merge(patches.into_iter().map(|patch| patch.mast.as_ref()))
            .map_err(CodePatchError::MastForestMerge)?;

        Self::new(Arc::new(mast))
    }

    /// Creates a new [`CodePatch`] from the MAST forest without validation.
    fn new_unchecked(mast: Arc<MastForest>) -> Self {
        let commitment = Hasher::hash_elements_in_domain(
            Word::words_as_elements(&[mast.interface_commitment(), mast.dependency_commitment()]),
            Kind::COMMITMENT_DOMAIN,
        );

        Self { mast, commitment, kind: PhantomData }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the MAST forest containing the created procedures.
    pub(crate) fn mast(&self) -> &Arc<MastForest> {
        &self.mast
    }

    /// Returns the set of created procedure roots.
    pub(crate) fn created_procedures(&self) -> BTreeSet<ProcedureRoot> {
        self.mast.procedure_digests().map(ProcedureRoot::from_raw).collect()
    }

    /// Returns the set of dependencies.
    pub(crate) fn dependencies(&self) -> BTreeSet<ProcedureRoot> {
        external_node_digests(&self.mast).map(ProcedureRoot::from_raw).collect()
    }

    /// Returns `true` if the patch creates no procedures.
    ///
    /// Such a patch has no dependencies either, since every node is reachable from a created
    /// procedure.
    pub(crate) fn is_empty(&self) -> bool {
        self.mast.procedure_roots().is_empty()
    }

    /// Returns the commitment to the created procedures.
    pub(crate) fn created_commitment(&self) -> Word {
        self.mast.interface_commitment()
    }

    /// Returns the commitment to the dependencies.
    pub(crate) fn dependencies_commitment(&self) -> Word {
        self.mast.dependency_commitment()
    }

    /// Returns the commitment to this patch.
    ///
    /// The commitment is the merge of [`Self::created_commitment`] and
    /// [`Self::dependencies_commitment`] in the [`CodePatchKind::CommitmentDomain`].
    pub(crate) fn commitment(&self) -> Word {
        self.commitment
    }
}

impl<Kind: CodePatchKind> Default for CodePatch<Kind> {
    fn default() -> Self {
        Self::new_unchecked(Arc::new(MastForest::new()))
    }
}

// HELPERS
// ================================================================================================

/// Returns an iterator over the digests of the external nodes of the forest.
fn external_node_digests(mast: &MastForest) -> impl Iterator<Item = Word> + '_ {
    mast.nodes().iter().filter(|node| node.is_external()).map(|node| node.digest())
}

/// Returns the set of procedure roots of the digests, or the first duplicated procedure root.
fn unique_procedure_roots(
    digests: impl Iterator<Item = Word>,
) -> Result<BTreeSet<ProcedureRoot>, ProcedureRoot> {
    let mut unique_roots = BTreeSet::new();
    for procedure_root in digests.map(ProcedureRoot::from_raw) {
        if !unique_roots.insert(procedure_root) {
            return Err(procedure_root);
        }
    }

    Ok(unique_roots)
}

/// Returns the digest of the first node of the forest that is not reachable from a procedure root,
/// if any.
fn find_unreachable_node(mast: &MastForest) -> Option<Word> {
    let mut is_reachable = vec![false; mast.nodes().len()];
    let mut pending_nodes = mast.procedure_roots().to_vec();

    while let Some(node_id) = pending_nodes.pop() {
        if let Some(reachable) = is_reachable.get_mut(u32::from(node_id) as usize)
            && !*reachable
        {
            *reachable = true;
            if let Some(node) = mast.get_node_by_id(node_id) {
                node.append_children_to(&mut pending_nodes);
            }
        }
    }

    mast.nodes()
        .iter()
        .zip(is_reachable)
        .find(|(_, reachable)| !reachable)
        .map(|(node, _)| node.digest())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use assert_matches::assert_matches;
    use miden_core::mast::{BasicBlockNodeBuilder, ExternalNodeBuilder, MastNode};
    use miden_core::operations::Operation;
    use rstest::rstest;

    use super::*;
    use crate::Felt;
    use crate::assembly::mast::MastNodeId;
    use crate::domain_registry::TRANSACTION_CODE_PATCH_COMMITMENT_DOMAIN;
    use crate::testing::assembler::assemble_test_package;
    use crate::transaction::TransactionCodePatch;
    use crate::utils::{IndexVec, create_external_node_forest};
    use crate::vm::AdviceMap;

    /// The core with the limits and the commitment domain of transaction patches.
    type CodePatch = super::CodePatch<TransactionCodePatch>;

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

    const NO_DEPENDENCIES_SOURCE: &str = "
        pub proc foo
            push.1 drop
        end

        pub proc bar
            push.2 drop
        end
    ";

    fn assemble_forest(source: &str) -> Arc<MastForest> {
        assemble_test_package("test-code-patch", "test::code_patch", source)
            .mast_forest()
            .clone()
    }

    /// Returns the basic block `push.value`, which has a distinct digest for every `value`.
    fn push_block(value: u32) -> anyhow::Result<MastNode> {
        Ok(BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(value))])
            .build()?
            .into())
    }

    /// Returns a patch whose created procedures are the basic blocks `push.value` of the values.
    fn push_block_patch(values: impl IntoIterator<Item = u32>) -> anyhow::Result<CodePatch> {
        let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
        let mut roots = Vec::new();
        for value in values {
            roots.push(nodes.push(push_block(value)?)?);
        }
        let mast = MastForest::from_raw_parts(nodes, roots, AdviceMap::default())?;

        Ok(CodePatch::new(Arc::new(mast))?)
    }

    /// Returns the sorted digests as a sequence of field elements.
    fn sorted_elements(digests: impl Iterator<Item = Word>) -> Vec<Felt> {
        let mut sorted_digests: Vec<Word> = digests.collect();
        sorted_digests.sort();
        sorted_digests.iter().flat_map(|digest| digest.as_elements().to_vec()).collect()
    }

    #[test]
    fn empty_patch_commits_to_empty_lists() -> anyhow::Result<()> {
        let patch = CodePatch::new(Arc::new(MastForest::new()))?;

        assert!(patch.is_empty());
        assert_eq!(patch.created_procedures().len(), 0);
        assert_eq!(patch.dependencies().len(), 0);
        let empty_list_commitment = Hasher::hash_elements::<Felt>(&[]);
        assert_eq!(
            patch.commitment(),
            Hasher::hash_elements_in_domain(
                Word::words_as_elements(&[empty_list_commitment, empty_list_commitment]),
                TRANSACTION_CODE_PATCH_COMMITMENT_DOMAIN,
            )
        );
        assert_eq!(patch, CodePatch::default());

        Ok(())
    }

    /// Pins the commitments to the sequential hash of the sorted roots, which the transaction
    /// kernel computes.
    #[rstest]
    #[case::with_dependencies(LIBRARY_SOURCE, vec![EXTERNAL_DIGEST])]
    #[case::without_dependencies(NO_DEPENDENCIES_SOURCE, Vec::new())]
    fn commitments_are_hashes_of_sorted_roots(
        #[case] source: &str,
        #[case] expected_dependencies: Vec<Word>,
    ) -> anyhow::Result<()> {
        let mast = assemble_forest(source);
        let patch = CodePatch::new(mast.clone())?;

        let mut expected_created_procedures: Vec<ProcedureRoot> =
            mast.procedure_digests().map(ProcedureRoot::from_raw).collect();
        expected_created_procedures.sort();
        let expected_created_commitment =
            Hasher::hash_elements(&sorted_elements(mast.procedure_digests()));
        let expected_dependencies_commitment =
            Hasher::hash_elements(&sorted_elements(expected_dependencies.iter().copied()));

        assert!(!patch.is_empty());
        assert_eq!(
            patch.created_procedures(),
            expected_created_procedures.into_iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            patch.dependencies(),
            expected_dependencies
                .into_iter()
                .map(ProcedureRoot::from_raw)
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(patch.created_commitment(), expected_created_commitment);
        assert_eq!(patch.dependencies_commitment(), expected_dependencies_commitment);
        assert_eq!(
            patch.commitment(),
            Hasher::hash_elements_in_domain(
                Word::words_as_elements(&[
                    expected_created_commitment,
                    expected_dependencies_commitment
                ]),
                TRANSACTION_CODE_PATCH_COMMITMENT_DOMAIN,
            )
        );

        Ok(())
    }

    #[test]
    fn merge_of_empty_patches_is_empty() -> anyhow::Result<()> {
        assert_eq!(CodePatch::merge::<TransactionCodePatch>([])?, CodePatch::default());
        assert_eq!(
            CodePatch::merge([&CodePatch::default(), &CodePatch::default()])?,
            CodePatch::default()
        );

        Ok(())
    }

    #[test]
    fn merge_deduplicates_overlapping_code() -> anyhow::Result<()> {
        let first_patch = push_block_patch([0, 1])?;
        let second_patch = push_block_patch([1, 2])?;

        let merged_patch = CodePatch::merge([&first_patch, &second_patch])?;

        assert_eq!(merged_patch.commitment(), push_block_patch([0, 1, 2])?.commitment());
        assert_eq!(merged_patch.mast().nodes().len(), 3);

        Ok(())
    }

    #[test]
    fn merge_deduplicates_shared_dependency() -> anyhow::Result<()> {
        let first_patch = CodePatch::new(assemble_forest(LIBRARY_SOURCE))?;
        let second_patch = CodePatch::new(assemble_forest(&format!(
            "
            pub proc baz
                push.3 drop
                call.{}
            end
            ",
            ProcedureRoot::from_raw(EXTERNAL_DIGEST)
        )))?;

        let merged_patch = CodePatch::merge([&first_patch, &second_patch])?;

        assert_eq!(merged_patch.created_procedures().len(), 3);
        assert_eq!(
            merged_patch.dependencies(),
            BTreeSet::from([ProcedureRoot::from_raw(EXTERNAL_DIGEST)])
        );

        Ok(())
    }

    /// A procedure that one patch creates and another one depends on is a created procedure of the
    /// merged patch. The insertion into the code tree is then a no-op, because the dependency
    /// proves that the procedure is present.
    #[test]
    fn merge_makes_dependency_created_procedure() -> anyhow::Result<()> {
        let creating_patch = CodePatch::new(assemble_forest(
            "
            pub proc foo
                push.1 drop
            end
            ",
        ))?;
        let foo_root = creating_patch
            .created_procedures()
            .pop_first()
            .ok_or_else(|| anyhow::anyhow!("patch should create foo"))?;
        let depending_patch = CodePatch::new(assemble_forest(&format!(
            "
            pub proc bar
                call.{foo_root}
            end
            "
        )))?;
        assert_eq!(depending_patch.dependencies(), BTreeSet::from([foo_root]));

        let merged_patch = CodePatch::merge([&creating_patch, &depending_patch])?;

        assert!(merged_patch.created_procedures().contains(&foo_root));
        assert_eq!(merged_patch.created_procedures().len(), 2);
        assert!(merged_patch.dependencies().is_empty());
        assert_eq!(
            CodePatch::merge([&depending_patch, &creating_patch])?.commitment(),
            merged_patch.commitment()
        );

        Ok(())
    }

    /// [`MastForest::merge`] keeps nodes with equal digests apart if their error codes differ, so
    /// the merged patch would create the procedure twice.
    #[test]
    fn merge_rejects_equal_procedures_with_different_error_codes() -> anyhow::Result<()> {
        let assert_patch = |error_code: u32| -> anyhow::Result<CodePatch> {
            let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
            let node_id = nodes.push(
                BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(error_code))])
                    .build()?
                    .into(),
            )?;
            let mast = MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())?;
            Ok(CodePatch::new(Arc::new(mast))?)
        };
        let first_patch = assert_patch(1)?;
        let second_patch = assert_patch(2)?;
        assert_eq!(first_patch.created_procedures(), second_patch.created_procedures());

        assert_matches!(
            CodePatch::merge([&first_patch, &second_patch]),
            Err(CodePatchError::DuplicateCreatedProcedure(root))
                if first_patch.created_procedures().contains(&root)
        );

        Ok(())
    }

    #[test]
    fn merge_rejects_too_many_created_procedures() -> anyhow::Result<()> {
        let max_roots = u32::try_from(TransactionCodePatch::MAX_ROOTS)?;
        let first_patch = push_block_patch(0..max_roots)?;
        let second_patch = push_block_patch([max_roots])?;

        assert_matches!(
            CodePatch::merge([&first_patch, &second_patch]),
            Err(CodePatchError::TooManyCreatedProcedures { count, .. })
                if count == TransactionCodePatch::MAX_ROOTS + 1
        );

        Ok(())
    }

    #[test]
    fn new_rejects_too_many_created_procedures() -> anyhow::Result<()> {
        let num_roots = TransactionCodePatch::MAX_ROOTS + 1;
        let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
        let mut roots = Vec::with_capacity(num_roots);
        for value in 0..num_roots {
            roots.push(nodes.push(push_block(u32::try_from(value)?)?)?);
        }
        let mast = MastForest::from_raw_parts(nodes, roots, AdviceMap::default())?;

        let error = CodePatch::new(Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::TooManyCreatedProcedures { count, .. } if count == num_roots
        );

        Ok(())
    }

    #[test]
    fn new_rejects_too_many_dependencies() -> anyhow::Result<()> {
        let num_external_nodes = TransactionCodePatch::MAX_ROOTS + 1;
        let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
        for value in 0..num_external_nodes {
            let digest = ProcedureRoot::mock(u32::try_from(value)?).as_word();
            nodes.push(ExternalNodeBuilder::new(digest).build().into())?;
        }
        let root = nodes.push(push_block(0)?)?;
        let mast = MastForest::from_raw_parts(nodes, vec![root], AdviceMap::default())?;

        let error = CodePatch::new(Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::TooManyDependencies { count, .. } if count == num_external_nodes
        );

        Ok(())
    }

    #[test]
    fn new_rejects_duplicate_created_procedure() -> anyhow::Result<()> {
        let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
        let node_id = nodes.push(push_block(0)?)?;
        let mast = MastForest::from_raw_parts(nodes, vec![node_id, node_id], AdviceMap::default())?;
        let duplicate_procedure = ProcedureRoot::from_raw(mast[node_id].digest());

        let error = CodePatch::new(Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::DuplicateCreatedProcedure(root) if root == duplicate_procedure
        );

        Ok(())
    }

    #[test]
    fn new_rejects_external_procedure_root() {
        let external_digest = Word::from([5, 6, 7, 8u32]);
        let (mast, _) = create_external_node_forest(external_digest);
        let external_root = ProcedureRoot::from_raw(external_digest);

        let error = CodePatch::new(Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::DependencyIsCreatedProcedure(root) if root == external_root
        );
    }

    #[test]
    fn new_rejects_unreachable_node() -> anyhow::Result<()> {
        let library = assemble_forest(LIBRARY_SOURCE);
        let foo_node_id = library
            .procedure_roots()
            .iter()
            .copied()
            .find(|&node_id| !matches!(library[node_id], MastNode::Call(_)))
            .ok_or_else(|| anyhow::anyhow!("foo should be a procedure root"))?;
        // Drop `bar` from the roots, so that it and its external node become unreachable.
        let mast = MastForest::from_raw_parts(
            library.nodes().to_vec().try_into()?,
            vec![foo_node_id],
            AdviceMap::default(),
        )?;

        let error = CodePatch::new(Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::UnreachableMastNode(digest) if digest == EXTERNAL_DIGEST
        );

        Ok(())
    }

    #[test]
    fn new_rejects_non_empty_advice_map() {
        let value = vec![Felt::ONE];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(Hasher::hash_elements(&value), value);
        let mast = MastForest::new().with_advice_map(advice_map);

        let error = CodePatch::new(Arc::new(mast)).unwrap_err();
        assert_matches!(error, CodePatchError::AdviceMapNotEmpty);
    }

    #[test]
    fn new_rejects_oversized_forest() -> anyhow::Result<()> {
        // Each push serializes its immediate, so the block exceeds the size limit.
        let push_count = TransactionCodePatch::MAX_SIZE as usize / size_of::<u64>();
        let operations = vec![Operation::Push(Felt::from_u32(u32::MAX)); push_count];
        let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
        let node_id = nodes.push(BasicBlockNodeBuilder::new(operations).build()?.into())?;
        let mast = MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())?;

        let error = CodePatch::new(Arc::new(mast)).unwrap_err();
        assert_matches!(
            error,
            CodePatchError::SizeLimitExceeded { size, .. } if size > TransactionCodePatch::MAX_SIZE as usize
        );

        Ok(())
    }
}
