use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::mast::{MastForest, MastNodeExt};
use miden_protocol::block::code_tree::{CodePatch, PartialCodeTree};
use miden_protocol::code::ProcedureRoot;

use crate::errors::TransactionKernelError;

mod procedure_extraction;
use procedure_extraction::ExtractProcedures;

// CODE PATCH SOURCE
// ================================================================================================

/// The code that a transaction can register, merged into one [`MastForest`].
///
/// The merge deduplicates nodes by digest and replaces an external node with the code of its
/// procedure if another forest contains it. Thus, building the [`CodePatch`] does not need to
/// follow references across forests.
pub(crate) struct CodePatchSource {
    mast_forest: MastForest,
}

impl CodePatchSource {
    /// Merges the provided forests into one source.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a forest has advice map entries, because the code tree and its registry do not store
    ///   advice.
    /// - the forests cannot be merged.
    pub(crate) fn new<'forest>(
        mast_forests: impl IntoIterator<Item = &'forest MastForest>,
    ) -> Result<Self, TransactionKernelError> {
        let mast_forests = mast_forests.into_iter().collect::<Vec<_>>();
        if mast_forests.iter().any(|mast_forest| !mast_forest.advice_map().is_empty()) {
            return Err(TransactionKernelError::CodePatchAdvice);
        }

        let (mast_forest, _) =
            MastForest::merge(mast_forests).map_err(TransactionKernelError::CodePatchMastForest)?;

        Ok(Self { mast_forest })
    }

    /// Returns the procedures whose code witnesses [`Self::build_code_patch`] needs.
    ///
    /// These are the procedure roots and the external nodes of the source. The caller must add
    /// the top-level roots whose code is not in the source.
    pub(crate) fn procedure_roots(&self) -> impl Iterator<Item = ProcedureRoot> + '_ {
        let external_nodes = self
            .mast_forest
            .nodes()
            .iter()
            .filter(|node| node.is_external())
            .map(MastNodeExt::digest);

        self.mast_forest
            .local_procedure_digests()
            .chain(external_nodes)
            .map(ProcedureRoot::from_raw)
    }

    /// Builds the [`CodePatch`] of the provided top-level procedure roots.
    ///
    /// The patch contains the code of each absent procedure that the top-level roots reach, as a
    /// procedure root. A reference to a present procedure becomes an external node, because its
    /// code is already registered, even if the source contains this code. A node is a reference
    /// if it is an external node or a procedure root. The assembler makes each compiled procedure
    /// a procedure root, and the MAST does not show which of them are exported. Thus, each
    /// procedure root is a separate procedure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the code witness of a top-level root or of a procedure in [`Self::procedure_roots`] is not
    ///   available. The kernel verifies the witness of each top-level root, so the host must have
    ///   it.
    /// - the code of an absent procedure is not in the source.
    /// - the patch is not a valid [`CodePatch`], e.g. because it exceeds [`CodePatch::MAX_SIZE`].
    pub(crate) fn build_code_patch(
        &self,
        top_level_roots: &BTreeSet<ProcedureRoot>,
        code_tree: &PartialCodeTree,
    ) -> Result<CodePatch, TransactionKernelError> {
        // Look up the presence of each procedure of the source once, so that the extraction can
        // decide which procedures to reference instead of copying.
        let mut present_roots = BTreeSet::new();
        for procedure_root in self.procedure_roots() {
            if is_present(code_tree, procedure_root)? {
                present_roots.insert(procedure_root.as_word());
            }
        }

        // Only absent top-level roots add code. The source must contain their code.
        let mut absent_top_level_nodes = Vec::new();
        for top_level_root in top_level_roots {
            if is_present(code_tree, *top_level_root)? {
                continue;
            }

            let node_id = self
                .mast_forest
                .find_procedure_root(top_level_root.as_word())
                .filter(|node_id| !self.mast_forest[*node_id].is_external())
                .ok_or(TransactionKernelError::MissingProcedureMast(*top_level_root))?;
            absent_top_level_nodes.push(node_id);
        }

        // Copy the code that the absent top-level roots reach, and reference present procedures.
        let mast_forest = self
            .mast_forest
            .extract_procedures(&absent_top_level_nodes, |digest| present_roots.contains(&digest))
            .map_err(TransactionKernelError::CodePatchMastForest)?;
        let code_patch = CodePatch::new(Arc::new(mast_forest))
            .map_err(TransactionKernelError::InvalidCodePatch)?;

        // The extraction keeps the external nodes of the source as dependencies. Such a node
        // references a procedure whose code the source does not contain, so the procedure must be
        // present.
        if let Some(absent_dependency) = code_patch
            .dependencies()
            .find(|dependency| !present_roots.contains(&dependency.as_word()))
        {
            return Err(TransactionKernelError::MissingProcedureMast(absent_dependency));
        }

        Ok(code_patch)
    }
}

/// Returns `true` if the procedure root is present in the code tree.
///
/// # Errors
///
/// Returns an error if the code witness of the procedure root is not available.
fn is_present(
    code_tree: &PartialCodeTree,
    procedure_root: ProcedureRoot,
) -> Result<bool, TransactionKernelError> {
    code_tree
        .contains(&procedure_root)
        .map_err(|source| TransactionKernelError::MissingCodeWitness { procedure_root, source })
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;

    use miden_protocol::assembly::Path;
    use miden_protocol::block::code_tree::CodeTree;
    use miden_protocol::testing::assembler::assemble_test_package;
    use miden_protocol::vm::AdviceMap;
    use miden_protocol::{CoreLibrary, Felt, Hasher, ProtocolLib};
    use miden_standards::StandardsLib;
    use miden_standards::account::wallets::BasicWallet;
    use miden_standards::note::{P2idNote, P2ideNote};

    use super::*;

    /// Returns a present procedure without MAST, which the test procedures call.
    fn present_root() -> ProcedureRoot {
        ProcedureRoot::mock(1)
    }

    /// Returns a present procedure that no test procedure references.
    fn unreferenced_root() -> ProcedureRoot {
        ProcedureRoot::mock(2)
    }

    /// `main` references the internal procedure `helper` and the present procedure. `helper` has
    /// control flow, so the assembler does not merge it into the basic block of `main`.
    fn main_source() -> String {
        format!(
            "
            proc helper
                if.true push.1 drop else push.2 drop end
            end

            pub proc main
                exec.helper
                call.{present_root}
            end
            ",
            present_root = present_root().as_word()
        )
    }

    /// `other` references a copy of the `helper` procedure of [`main_source`].
    const OTHER_SOURCE: &str = "
        proc helper
            if.true push.1 drop else push.2 drop end
        end

        pub proc other
            exec.helper
            push.3 drop
        end
    ";

    /// Assembles the source and returns its forest and the root of its exported procedure.
    fn assemble_procedure(
        source: &str,
        name: &str,
    ) -> anyhow::Result<(Arc<MastForest>, ProcedureRoot)> {
        let package = assemble_test_package("test-code-patch", "test::code_patch", source);
        let digest = package
            .get_procedure_root_by_path(Path::new(&format!("test::code_patch::{name}")))
            .ok_or_else(|| anyhow::anyhow!("test source does not export {name}"))?;

        Ok((Arc::clone(package.mast_forest()), ProcedureRoot::from_raw(digest)))
    }

    fn local_roots(mast_forest: &MastForest) -> BTreeSet<ProcedureRoot> {
        mast_forest.local_procedure_digests().map(ProcedureRoot::from_raw).collect()
    }

    fn code_patch_source(mast_forests: &[Arc<MastForest>]) -> anyhow::Result<CodePatchSource> {
        Ok(CodePatchSource::new(mast_forests.iter().map(Arc::as_ref))?)
    }

    /// Returns a partial tree of a tree with the present roots that tracks the provided roots.
    fn partial_code_tree(
        present_roots: impl IntoIterator<Item = ProcedureRoot>,
        tracked_roots: impl IntoIterator<Item = ProcedureRoot>,
    ) -> anyhow::Result<PartialCodeTree> {
        let code_tree = CodeTree::with_entries(present_roots)?;
        Ok(PartialCodeTree::with_witnesses(
            tracked_roots.into_iter().map(|root| code_tree.open(&root)),
        )?)
    }

    #[test]
    fn patch_contains_absent_code_and_references_present_code() -> anyhow::Result<()> {
        let (main_forest, main_root) = assemble_procedure(&main_source(), "main")?;
        let absent_roots = local_roots(&main_forest);
        // helper is a separate procedure root of the forest
        assert_eq!(absent_roots.len(), 2);

        let source = code_patch_source(&[main_forest])?;
        let source_roots = source.procedure_roots().collect::<BTreeSet<_>>();
        let mut expected_source_roots = absent_roots.clone();
        expected_source_roots.insert(present_root());
        assert_eq!(source_roots, expected_source_roots);

        let code_tree = partial_code_tree(
            [present_root(), unreferenced_root()],
            source_roots.iter().copied().chain([unreferenced_root()]),
        )?;
        let top_level_roots = BTreeSet::from([main_root, present_root(), unreferenced_root()]);

        let code_patch = source.build_code_patch(&top_level_roots, &code_tree)?;

        assert_eq!(code_patch.created_procedures().collect::<BTreeSet<_>>(), absent_roots);
        // a present top-level root is in the patch only if absent code references it
        assert_eq!(code_patch.dependencies().collect::<Vec<_>>(), [present_root()]);

        Ok(())
    }

    #[test]
    fn shared_procedure_is_copied_once() -> anyhow::Result<()> {
        let (main_forest, main_root) = assemble_procedure(&main_source(), "main")?;
        let (other_forest, other_root) = assemble_procedure(OTHER_SOURCE, "other")?;

        // both forests contain helper, so the absent roots are main, other and helper
        let absent_roots =
            local_roots(&main_forest).union(&local_roots(&other_forest)).copied().collect();
        let code_tree = partial_code_tree(
            [present_root()],
            [main_root, other_root, present_root()]
                .into_iter()
                .chain(local_roots(&main_forest))
                .chain(local_roots(&other_forest)),
        )?;

        let code_patch = code_patch_source(&[main_forest, other_forest])?
            .build_code_patch(&BTreeSet::from([main_root, other_root]), &code_tree)?;

        assert_eq!(code_patch.created_procedures().collect::<BTreeSet<_>>(), absent_roots);
        assert_eq!(code_patch.created_procedures().count(), 3);

        Ok(())
    }

    #[test]
    fn missing_mast_or_witness_is_an_error() -> anyhow::Result<()> {
        let (main_forest, main_root) = assemble_procedure(&main_source(), "main")?;
        let top_level_roots = BTreeSet::from([main_root]);

        let code_tree = partial_code_tree(
            [present_root()],
            local_roots(&main_forest).into_iter().chain([present_root()]),
        )?;
        let result = code_patch_source(&[])?.build_code_patch(&top_level_roots, &code_tree);
        assert!(matches!(
            result,
            Err(TransactionKernelError::MissingProcedureMast(root)) if root == main_root
        ));

        // the leaf of the present root is not empty, so the partial tree cannot deduce it
        let code_tree = partial_code_tree([present_root()], local_roots(&main_forest))?;
        let source = code_patch_source(&[main_forest])?;
        let result = source.build_code_patch(&top_level_roots, &code_tree);
        assert!(matches!(
            result,
            Err(TransactionKernelError::MissingCodeWitness { procedure_root, .. })
                if procedure_root == present_root()
        ));

        // the external node of the present root has no code, so the root must be present
        let code_tree = partial_code_tree([], source.procedure_roots())?;
        let result = source.build_code_patch(&top_level_roots, &code_tree);
        assert!(matches!(
            result,
            Err(TransactionKernelError::MissingProcedureMast(root)) if root == present_root()
        ));

        Ok(())
    }

    /// The forest of main contains the code of helper, but helper is present, so the patch
    /// references it.
    #[test]
    fn present_procedure_root_is_referenced() -> anyhow::Result<()> {
        let (main_forest, main_root) = assemble_procedure(&main_source(), "main")?;
        let mut helper_roots = local_roots(&main_forest);
        helper_roots.remove(&main_root);
        let source = code_patch_source(&[main_forest])?;

        let code_tree = partial_code_tree(
            helper_roots.iter().copied().chain([present_root()]),
            source.procedure_roots(),
        )?;
        let code_patch = source.build_code_patch(&BTreeSet::from([main_root]), &code_tree)?;

        assert_eq!(code_patch.created_procedures().collect::<Vec<_>>(), [main_root]);
        let mut expected_dependencies = helper_roots;
        expected_dependencies.insert(present_root());
        assert_eq!(code_patch.dependencies().collect::<BTreeSet<_>>(), expected_dependencies);

        Ok(())
    }

    #[test]
    fn code_with_advice_is_rejected() {
        let value = [Felt::ONE];
        let mut advice_map = AdviceMap::default();
        advice_map.insert(Hasher::hash_elements(&value), value.to_vec());
        let mast_forest = Arc::new(MastForest::new().with_advice_map(advice_map));

        let result = code_patch_source(&[mast_forest]);
        assert!(matches!(
            result.map_err(|error| error.downcast::<TransactionKernelError>()),
            Err(Ok(TransactionKernelError::CodePatchAdvice))
        ));
    }

    #[test]
    fn empty_top_level_roots_give_empty_patch() -> anyhow::Result<()> {
        let code_tree = partial_code_tree([present_root()], [])?;
        let code_patch = code_patch_source(&[])?.build_code_patch(&BTreeSet::new(), &code_tree)?;

        assert!(code_patch.is_empty());
        assert_eq!(code_patch, CodePatch::default());

        Ok(())
    }

    /// The example of building the `CodePatch` in the design of the code tree: the tree contains
    /// the core and protocol libraries, but not miden-standards.
    #[test]
    fn patch_of_standard_note_scripts() -> anyhow::Result<()> {
        let library_forests = [
            CoreLibrary::default().package(),
            ProtocolLib::default().package(),
            StandardsLib::default().package(),
        ]
        .map(|package| Arc::clone(package.mast_forest()));
        let [core_forest, protocol_forest, standards_forest] = &library_forests;
        let note_scripts = [P2idNote::script(), P2ideNote::script()];
        let note_script_roots = note_scripts
            .iter()
            .map(|note_script| ProcedureRoot::from_raw(note_script.root().into()))
            .collect::<BTreeSet<_>>();
        let receive_asset_root = ProcedureRoot::from_raw(BasicWallet::receive_asset_root().into());

        let registered_roots = local_roots(core_forest)
            .union(&local_roots(protocol_forest))
            .copied()
            .collect::<BTreeSet<_>>();
        let tracked_roots = library_forests
            .iter()
            .flat_map(|mast_forest| local_roots(mast_forest))
            .chain(note_script_roots.iter().copied())
            .collect::<BTreeSet<_>>();
        let mut source_forests = library_forests.to_vec();
        source_forests.extend(note_scripts.iter().map(|note_script| note_script.mast()));
        let source = code_patch_source(&source_forests)?;

        // the note scripts and the wallet procedure that they use are created
        let code_tree =
            partial_code_tree(registered_roots.iter().copied(), tracked_roots.iter().copied())?;
        let code_patch = source.build_code_patch(&note_script_roots, &code_tree)?;

        let created_procedures = code_patch.created_procedures().collect::<BTreeSet<_>>();
        assert!(created_procedures.is_superset(&note_script_roots));
        assert!(created_procedures.contains(&receive_asset_root));
        assert!(created_procedures.is_subset(&local_roots(standards_forest)));
        assert!(code_patch.dependencies().all(|root| registered_roots.contains(&root)));

        // a registered wallet procedure is a dependency
        let code_tree = partial_code_tree(
            registered_roots.iter().copied().chain([receive_asset_root]),
            tracked_roots.iter().copied(),
        )?;
        let code_patch = source.build_code_patch(&note_script_roots, &code_tree)?;

        assert!(!code_patch.created_procedures().any(|root| root == receive_asset_root));
        assert!(code_patch.dependencies().any(|root| root == receive_asset_root));

        Ok(())
    }
}
