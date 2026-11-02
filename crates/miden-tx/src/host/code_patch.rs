use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::advice::AdviceMutation;
use miden_processor::mast::{MastForest, MastNode, MastNodeExt, MastNodeId};
use miden_protocol::Felt;
use miden_protocol::block::code_tree::{CodeWitness, PartialCodeTree};
use miden_protocol::code::ProcedureRoot;
use miden_protocol::vm::AdviceMap;

use crate::errors::TransactionKernelError;

// CODE PATCH LISTS
// ================================================================================================

/// The procedure roots of the code patch that the transaction kernel creates.
///
/// The lists are sorted, because the kernel asserts that they are unique and sorted. The advice
/// stack layout is defined in `code_patch::create` in the transaction kernel.
#[derive(Debug, Default)]
pub(crate) struct CodePatchLists {
    /// The top-level procedure roots that are present in the code tree.
    existing_procedures: BTreeSet<ProcedureRoot>,
    /// The procedure roots that are absent from the code tree.
    created_procedures: BTreeSet<ProcedureRoot>,
    /// The present procedure roots that a created procedure references.
    dependencies: BTreeSet<ProcedureRoot>,
}

impl CodePatchLists {
    /// Builds the code patch lists of the provided top-level procedure roots.
    ///
    /// The procedures that an absent procedure references are walked through its MAST, which
    /// `resolve_mast` returns. The walk stops at present procedures, because their code is
    /// already registered.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the code witness of a procedure root is not available in the code tree.
    /// - the MAST of an absent procedure is not available.
    pub fn new(
        top_level_roots: impl IntoIterator<Item = ProcedureRoot>,
        code_tree: &PartialCodeTree,
        resolve_mast: impl Fn(ProcedureRoot) -> Option<(Arc<MastForest>, MastNodeId)>,
    ) -> Result<Self, TransactionKernelError> {
        let mut lists = Self::default();

        for top_level_root in top_level_roots {
            if is_present(code_tree, &top_level_root)? {
                lists.existing_procedures.insert(top_level_root);
                continue;
            }

            // the procedures that an absent root references are walked only once
            if !lists.created_procedures.insert(top_level_root) {
                continue;
            }

            let referenced_procedures = referenced_procedures(
                top_level_root,
                &resolve_mast,
                |procedure_root| Ok(!is_present(code_tree, &procedure_root)?),
                true,
            )?;

            for referenced_root in referenced_procedures {
                if is_present(code_tree, &referenced_root)? {
                    lists.dependencies.insert(referenced_root);
                } else {
                    lists.created_procedures.insert(referenced_root);
                }
            }
        }

        Ok(lists)
    }

    /// Returns the advice that the kernel reads to create the code patch and the code witnesses
    /// that it verifies.
    ///
    /// # Errors
    ///
    /// Returns an error if the code witness of a procedure root is not available in the code tree.
    pub fn into_advice(
        self,
        code_tree: &PartialCodeTree,
    ) -> Result<(Vec<AdviceMutation>, Vec<CodeWitness>), TransactionKernelError> {
        let lists = [&self.existing_procedures, &self.created_procedures, &self.dependencies];

        let mut advice_stack = Vec::new();
        for list in lists {
            advice_stack.push(Felt::from(list.len() as u32));
            advice_stack.extend(list.iter().flat_map(|procedure_root| procedure_root.as_word()));
        }

        // a present top-level root can also be a dependency, but needs only one witness
        let procedure_roots: BTreeSet<&ProcedureRoot> = lists.into_iter().flatten().collect();

        let mut witnesses = Vec::with_capacity(procedure_roots.len());
        let mut merkle_store_nodes = Vec::new();
        let mut advice_map = AdviceMap::default();
        for procedure_root in procedure_roots {
            let witness = code_tree.open(procedure_root).map_err(|source| {
                TransactionKernelError::MissingCodeWitness {
                    procedure_root: *procedure_root,
                    source,
                }
            })?;

            let proof = witness.proof();
            merkle_store_nodes.extend(proof.authenticated_nodes());
            advice_map
                .insert(proof.leaf().hash(), proof.leaf().to_elements().collect::<Arc<[Felt]>>());
            witnesses.push(witness);
        }

        let mutations = Vec::from([
            AdviceMutation::extend_merkle_store(merkle_store_nodes),
            AdviceMutation::extend_map(advice_map),
            AdviceMutation::extend_advice_stack_with(advice_stack),
        ]);

        Ok((mutations, witnesses))
    }
}

/// Returns `true` if the procedure root is present in the code tree.
///
/// # Errors
///
/// Returns an error if the code witness of the procedure root is not available.
fn is_present(
    code_tree: &PartialCodeTree,
    procedure_root: &ProcedureRoot,
) -> Result<bool, TransactionKernelError> {
    code_tree.contains(procedure_root).map_err(|source| {
        TransactionKernelError::MissingCodeWitness { procedure_root: *procedure_root, source }
    })
}

// REFERENCED PROCEDURES
// ================================================================================================

/// Returns the procedures that the code of the provided procedure root references, directly or
/// indirectly.
///
/// The referenced procedures are the external nodes that the code reaches. Other procedure roots
/// of a forest are not separate procedures, because the host cannot tell exported procedures
/// from internal ones.
///
/// - `resolve_mast` returns the MAST of a procedure root, if it is available.
/// - `should_descend` decides whether the walk continues into the code of a referenced procedure.
/// - If `require_mast` is `true`, missing MAST of the root or of a procedure into which the walk
///   descends is an error. Otherwise, such procedures are skipped.
pub(crate) fn referenced_procedures(
    procedure_root: ProcedureRoot,
    resolve_mast: impl Fn(ProcedureRoot) -> Option<(Arc<MastForest>, MastNodeId)>,
    mut should_descend: impl FnMut(ProcedureRoot) -> Result<bool, TransactionKernelError>,
    require_mast: bool,
) -> Result<Vec<ProcedureRoot>, TransactionKernelError> {
    let mut referenced_procedures = Vec::new();
    let mut visited_procedures = BTreeSet::from([procedure_root]);
    let mut pending_procedures = Vec::from([procedure_root]);

    while let Some(pending_procedure) = pending_procedures.pop() {
        let Some((mast_forest, node_id)) = resolve_mast(pending_procedure) else {
            if require_mast {
                return Err(TransactionKernelError::MissingProcedureMast(pending_procedure));
            }
            continue;
        };

        for external_procedure in external_procedures(&mast_forest, node_id) {
            if visited_procedures.insert(external_procedure) {
                referenced_procedures.push(external_procedure);
                if should_descend(external_procedure)? {
                    pending_procedures.push(external_procedure);
                }
            }
        }
    }

    Ok(referenced_procedures)
}

/// Returns the digests of the external nodes that the node with the provided ID reaches in the
/// forest.
fn external_procedures(mast_forest: &MastForest, node_id: MastNodeId) -> Vec<ProcedureRoot> {
    let mut external_procedures = Vec::new();
    let mut visited_nodes = BTreeSet::new();
    let mut pending_nodes = Vec::from([node_id]);

    while let Some(pending_node) = pending_nodes.pop() {
        if !visited_nodes.insert(pending_node) {
            continue;
        }

        match &mast_forest[pending_node] {
            MastNode::External(external_node) => {
                external_procedures.push(ProcedureRoot::from_raw(external_node.digest()));
            },
            node => node.for_each_child(|child| pending_nodes.push(child)),
        }
    }

    external_procedures
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::block::code_tree::CodeTree;

    use super::*;

    #[test]
    fn lists_split_top_level_roots_by_presence() -> anyhow::Result<()> {
        let present_root = ProcedureRoot::mock(0);
        let absent_root = ProcedureRoot::mock(1);
        let code_tree = CodeTree::with_entries([present_root])?;
        let partial_code_tree = PartialCodeTree::with_witnesses(
            [present_root, absent_root].map(|root| code_tree.open(&root)),
        )?;

        let lists = CodePatchLists::new([present_root], &partial_code_tree, |_| None)?;
        assert_eq!(lists.existing_procedures, BTreeSet::from([present_root]));
        assert!(lists.created_procedures.is_empty());

        // an absent root needs its MAST to find the procedures it references
        assert!(matches!(
            CodePatchLists::new([absent_root], &partial_code_tree, |_| None),
            Err(TransactionKernelError::MissingProcedureMast(root)) if root == absent_root
        ));

        // a partial code tree without the witness cannot determine the presence
        let empty_partial_code_tree = PartialCodeTree::new(code_tree.root());
        assert!(matches!(
            CodePatchLists::new([present_root], &empty_partial_code_tree, |_| None),
            Err(TransactionKernelError::MissingCodeWitness { procedure_root, .. })
                if procedure_root == present_root
        ));

        Ok(())
    }

    #[test]
    fn referenced_procedures_require_mast_only_if_requested() -> anyhow::Result<()> {
        let procedure_root = ProcedureRoot::mock(0);

        let referenced = referenced_procedures(procedure_root, |_| None, |_| Ok(true), false)?;
        assert!(referenced.is_empty());

        assert!(matches!(
            referenced_procedures(procedure_root, |_| None, |_| Ok(true), true),
            Err(TransactionKernelError::MissingProcedureMast(root)) if root == procedure_root
        ));

        Ok(())
    }
}
