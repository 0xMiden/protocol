use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::mast::{
    DenseMastForestBuilder,
    ExternalNodeBuilder,
    MastForest,
    MastNodeExt,
    MastNodeId,
    build_node_with_remapped_ids,
};
use miden_protocol::Word;
use miden_protocol::block::code_tree::{CodePatch, PartialCodeTree};
use miden_protocol::code::ProcedureRoot;

use crate::errors::TransactionKernelError;

// REFERENCED PROCEDURES
// ================================================================================================

/// Returns the procedures that the code of the provided procedure root references, directly or
/// indirectly.
///
/// The host requests the code witnesses of these procedures before it knows which of them are
/// present. Thus, the walk does not stop at present procedures. A procedure whose MAST is not
/// available is in the result, but the walk does not continue into its code.
///
/// See [`build_code_patch`] for the requirements on `resolve_mast`.
pub(crate) fn referenced_procedures(
    procedure_root: ProcedureRoot,
    resolve_mast: impl Fn(ProcedureRoot) -> Option<(Arc<MastForest>, MastNodeId)>,
) -> BTreeSet<ProcedureRoot> {
    let mut referenced_procedures = BTreeSet::new();
    let mut pending_procedures = Vec::from([procedure_root]);

    while let Some(pending_procedure) = pending_procedures.pop() {
        let Some((mast_forest, procedure_node)) = resolve_mast(pending_procedure) else {
            continue;
        };

        for reference in procedure_references(&mast_forest, procedure_node) {
            if referenced_procedures.insert(reference) {
                pending_procedures.push(reference);
            }
        }
    }

    referenced_procedures
}

/// Returns the procedures that the code of the procedure with the provided root node references
/// directly.
fn procedure_references(
    mast_forest: &MastForest,
    procedure_node: MastNodeId,
) -> BTreeSet<ProcedureRoot> {
    let mut references = BTreeSet::new();
    let mut visited_nodes = BTreeSet::new();
    let mut pending_nodes = Vec::from([procedure_node]);

    while let Some(pending_node) = pending_nodes.pop() {
        if !visited_nodes.insert(pending_node) {
            continue;
        }

        match node_reference(mast_forest, pending_node, procedure_node) {
            Some(reference) => {
                references.insert(reference);
            },
            None => mast_forest[pending_node].for_each_child(|child| pending_nodes.push(child)),
        }
    }

    references
}

/// Returns the procedure root that the node references, if the node is a reference in the code of
/// the procedure with the provided root node.
///
/// A node is a reference if it is an external node or another procedure root of the forest. The
/// assembler makes each compiled procedure a procedure root, and the MAST does not show which of
/// them are exported. Thus, each procedure root is a separate procedure.
fn node_reference(
    mast_forest: &MastForest,
    node_id: MastNodeId,
    procedure_node: MastNodeId,
) -> Option<ProcedureRoot> {
    let node = &mast_forest[node_id];
    let is_reference =
        node_id != procedure_node && (node.is_external() || mast_forest.is_procedure_root(node_id));

    is_reference.then(|| ProcedureRoot::from_raw(node.digest()))
}

// CODE PATCH CONSTRUCTION
// ================================================================================================

/// Builds the [`CodePatch`] of the provided top-level procedure roots.
///
/// The patch contains the code of each absent procedure that the top-level roots reach, as a
/// procedure root. A reference to a present procedure becomes an external node, because its code
/// is already registered. Thus, the walk stops at present procedures.
///
/// `resolve_mast` returns the MAST forest and the root node of the code of a procedure, if it is
/// available. The node must not be an external node, because such a node only references the
/// code. `resolve_mast` must also provide the procedures that a forest does not export, because
/// code references each procedure root of a forest.
///
/// Also returns the present top-level roots that are not dependencies of the patch. The kernel
/// finds the other present top-level roots in the dependencies, so it needs only one witness for
/// each of them.
///
/// # Errors
///
/// Returns an error if:
/// - the code witness of a top-level root or of a procedure that absent code references is not
///   available.
/// - the MAST of an absent procedure is not available.
/// - the patch is not a valid [`CodePatch`], e.g. because it exceeds [`CodePatch::MAX_SIZE`].
pub(crate) fn build_code_patch(
    top_level_roots: &BTreeSet<ProcedureRoot>,
    code_tree: &PartialCodeTree,
    resolve_mast: impl Fn(ProcedureRoot) -> Option<(Arc<MastForest>, MastNodeId)>,
) -> Result<(CodePatch, BTreeSet<ProcedureRoot>), TransactionKernelError> {
    let mut patch_builder = CodePatchBuilder::new(code_tree, resolve_mast);
    let mut present_roots = BTreeSet::new();

    for top_level_root in top_level_roots {
        if is_present(code_tree, *top_level_root)? {
            present_roots.insert(*top_level_root);
        } else {
            patch_builder.copy_procedure(*top_level_root)?;
        }
    }

    let code_patch = patch_builder.build()?;
    let dependencies = code_patch.dependencies().collect::<BTreeSet<_>>();
    let existing_procedures = present_roots.difference(&dependencies).copied().collect();

    Ok((code_patch, existing_procedures))
}

/// Copies the code of absent procedures into the MAST forest of a [`CodePatch`].
struct CodePatchBuilder<'tree, ResolveMast> {
    code_tree: &'tree PartialCodeTree,
    resolve_mast: ResolveMast,
    forest_builder: DenseMastForestBuilder,
    /// The nodes of the patch forest by digest, so that each node is copied only once, also if
    /// multiple source forests contain it.
    copied_nodes: BTreeMap<Word, MastNodeId>,
}

/// A step of the post-order copy of a node.
enum CopyStep {
    /// Copies the children of the node, or makes the node an external node or a procedure.
    Enter(SourceNode),
    /// Copies the node after its children.
    Exit(SourceNode),
}

/// A node of a source forest in the code of the procedure with the root node `procedure_node`.
struct SourceNode {
    mast_forest: Arc<MastForest>,
    node_id: MastNodeId,
    procedure_node: MastNodeId,
}

impl<'tree, ResolveMast> CodePatchBuilder<'tree, ResolveMast>
where
    ResolveMast: Fn(ProcedureRoot) -> Option<(Arc<MastForest>, MastNodeId)>,
{
    fn new(code_tree: &'tree PartialCodeTree, resolve_mast: ResolveMast) -> Self {
        Self {
            code_tree,
            resolve_mast,
            forest_builder: DenseMastForestBuilder::new(),
            copied_nodes: BTreeMap::new(),
        }
    }

    /// Copies the code of the absent procedure and of the absent procedures that it references.
    fn copy_procedure(
        &mut self,
        procedure_root: ProcedureRoot,
    ) -> Result<(), TransactionKernelError> {
        let mut pending_steps = Vec::new();
        self.enter_procedure(procedure_root, &mut pending_steps)?;

        while let Some(step) = pending_steps.pop() {
            match step {
                CopyStep::Enter(source_node) => self.enter_node(source_node, &mut pending_steps)?,
                CopyStep::Exit(source_node) => self.exit_node(&source_node)?,
            }
        }

        Ok(())
    }

    /// Schedules the copy of an absent procedure, unless the patch already contains its code.
    fn enter_procedure(
        &mut self,
        procedure_root: ProcedureRoot,
        pending_steps: &mut Vec<CopyStep>,
    ) -> Result<(), TransactionKernelError> {
        if let Some(copied_node) = self.copied_nodes.get(&procedure_root.as_word()) {
            self.forest_builder.mark_root(*copied_node);
            return Ok(());
        }

        let (mast_forest, procedure_node) = (self.resolve_mast)(procedure_root)
            .ok_or(TransactionKernelError::MissingProcedureMast(procedure_root))?;
        pending_steps.push(CopyStep::Enter(SourceNode {
            mast_forest,
            node_id: procedure_node,
            procedure_node,
        }));

        Ok(())
    }

    fn enter_node(
        &mut self,
        source_node: SourceNode,
        pending_steps: &mut Vec<CopyStep>,
    ) -> Result<(), TransactionKernelError> {
        let SourceNode { mast_forest, node_id, procedure_node } = &source_node;

        if let Some(reference) = node_reference(mast_forest, *node_id, *procedure_node) {
            if !is_present(self.code_tree, reference)? {
                return self.enter_procedure(reference, pending_steps);
            }

            if !self.copied_nodes.contains_key(&reference.as_word()) {
                let external_node = self
                    .forest_builder
                    .push_node(ExternalNodeBuilder::new(reference.as_word()))
                    .map_err(TransactionKernelError::CodePatchMastForest)?;
                self.copied_nodes.insert(reference.as_word(), external_node);
            }

            return Ok(());
        }

        let digest = mast_forest[*node_id].digest();
        if let Some(copied_node) = self.copied_nodes.get(&digest) {
            if node_id == procedure_node {
                self.forest_builder.mark_root(*copied_node);
            }
            return Ok(());
        }

        let mut child_steps = Vec::new();
        mast_forest[*node_id].for_each_child(|child| {
            child_steps.push(CopyStep::Enter(SourceNode {
                mast_forest: Arc::clone(mast_forest),
                node_id: child,
                procedure_node: *procedure_node,
            }))
        });

        pending_steps.push(CopyStep::Exit(source_node));
        pending_steps.extend(child_steps);

        Ok(())
    }

    fn exit_node(&mut self, source_node: &SourceNode) -> Result<(), TransactionKernelError> {
        let SourceNode { mast_forest, node_id, procedure_node } = source_node;
        let node = &mast_forest[*node_id];
        let digest = node.digest();

        let mut child_mapping = BTreeMap::new();
        let mut missing_child = None;
        node.for_each_child(|child| match self.copied_nodes.get(&mast_forest[child].digest()) {
            Some(copied_child) => {
                child_mapping.insert(child, *copied_child);
            },
            None => missing_child = Some(mast_forest[child].digest()),
        });
        // unreachable, because the children are copied before their parent
        if let Some(missing_child) = missing_child {
            return Err(TransactionKernelError::other(format!(
                "child {missing_child} of a code patch node was not copied before its parent"
            )));
        }

        let node_builder =
            build_node_with_remapped_ids(*node_id, node.clone(), mast_forest, &child_mapping)
                .map_err(TransactionKernelError::CodePatchMastForest)?;
        let copied_node = self
            .forest_builder
            .push_node(node_builder)
            .map_err(TransactionKernelError::CodePatchMastForest)?;
        self.copied_nodes.insert(digest, copied_node);

        if node_id == procedure_node {
            self.forest_builder.mark_root(copied_node);
        }

        Ok(())
    }

    fn build(self) -> Result<CodePatch, TransactionKernelError> {
        let mast_forest = self
            .forest_builder
            .build()
            .map_err(TransactionKernelError::CodePatchMastForest)?;

        CodePatch::new(Arc::new(mast_forest)).map_err(TransactionKernelError::InvalidCodePatch)
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
    use miden_protocol::{CoreLibrary, ProtocolLib};
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

    /// Returns a resolver that finds the code of a procedure root in the provided forests.
    fn resolver(
        mast_forests: Vec<Arc<MastForest>>,
    ) -> impl Fn(ProcedureRoot) -> Option<(Arc<MastForest>, MastNodeId)> {
        move |procedure_root| {
            mast_forests.iter().find_map(|mast_forest| {
                mast_forest
                    .find_procedure_root(procedure_root.as_word())
                    .filter(|node_id| !mast_forest[*node_id].is_external())
                    .map(|node_id| (Arc::clone(mast_forest), node_id))
            })
        }
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

        let code_tree = partial_code_tree(
            [present_root(), unreferenced_root()],
            absent_roots.iter().copied().chain([present_root(), unreferenced_root()]),
        )?;
        let top_level_roots = BTreeSet::from([main_root, present_root(), unreferenced_root()]);

        let (code_patch, existing_procedures) =
            build_code_patch(&top_level_roots, &code_tree, resolver(vec![main_forest]))?;

        assert_eq!(code_patch.created_procedures().collect::<BTreeSet<_>>(), absent_roots);
        assert_eq!(code_patch.dependencies().collect::<Vec<_>>(), [present_root()]);
        // the kernel finds the present root that main references in the dependencies
        assert_eq!(existing_procedures, BTreeSet::from([unreferenced_root()]));

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

        let (code_patch, _) = build_code_patch(
            &BTreeSet::from([main_root, other_root]),
            &code_tree,
            resolver(vec![main_forest, other_forest]),
        )?;

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
        let result = build_code_patch(&top_level_roots, &code_tree, resolver(Vec::new()));
        assert!(matches!(
            result,
            Err(TransactionKernelError::MissingProcedureMast(root)) if root == main_root
        ));

        // the leaf of the present root is not empty, so the partial tree cannot deduce it
        let code_tree = partial_code_tree([present_root()], local_roots(&main_forest))?;
        let result = build_code_patch(&top_level_roots, &code_tree, resolver(vec![main_forest]));
        assert!(matches!(
            result,
            Err(TransactionKernelError::MissingCodeWitness { procedure_root, .. })
                if procedure_root == present_root()
        ));

        Ok(())
    }

    #[test]
    fn referenced_procedures_skip_missing_mast() -> anyhow::Result<()> {
        let (main_forest, main_root) = assemble_procedure(&main_source(), "main")?;
        let mut expected_references = local_roots(&main_forest);
        expected_references.remove(&main_root);
        expected_references.insert(present_root());

        // the walk does not descend into the present root, because its MAST is not available
        let references = referenced_procedures(main_root, resolver(vec![main_forest]));
        assert_eq!(references, expected_references);

        assert!(referenced_procedures(main_root, resolver(Vec::new())).is_empty());

        Ok(())
    }

    #[test]
    fn empty_top_level_roots_give_empty_patch() -> anyhow::Result<()> {
        let code_tree = partial_code_tree([present_root()], [])?;
        let (code_patch, existing_procedures) =
            build_code_patch(&BTreeSet::new(), &code_tree, resolver(Vec::new()))?;

        assert!(code_patch.is_empty());
        assert_eq!(code_patch, CodePatch::default());
        assert!(existing_procedures.is_empty());

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

        // the note scripts and the wallet procedure that they use are created
        let code_tree =
            partial_code_tree(registered_roots.iter().copied(), tracked_roots.iter().copied())?;
        let (code_patch, existing_procedures) =
            build_code_patch(&note_script_roots, &code_tree, resolver(source_forests.clone()))?;

        let created_procedures = code_patch.created_procedures().collect::<BTreeSet<_>>();
        assert!(created_procedures.is_superset(&note_script_roots));
        assert!(created_procedures.contains(&receive_asset_root));
        assert!(created_procedures.is_subset(&local_roots(standards_forest)));
        assert!(code_patch.dependencies().all(|root| registered_roots.contains(&root)));
        assert!(existing_procedures.is_empty());

        // a registered wallet procedure is a dependency
        let code_tree = partial_code_tree(
            registered_roots.iter().copied().chain([receive_asset_root]),
            tracked_roots.iter().copied(),
        )?;
        let (code_patch, _) =
            build_code_patch(&note_script_roots, &code_tree, resolver(source_forests))?;

        assert!(!code_patch.created_procedures().any(|root| root == receive_asset_root));
        assert!(code_patch.dependencies().any(|root| root == receive_asset_root));

        Ok(())
    }
}
