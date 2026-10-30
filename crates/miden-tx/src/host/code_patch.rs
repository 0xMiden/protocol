use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::advice::AdviceMutation;
use miden_processor::mast::{MastForest, MastNode, MastNodeExt, MastNodeId};
use miden_protocol::Felt;
use miden_protocol::block::code_tree::{CodeWitness, PartialCodeTree};
use miden_protocol::code::ProcedureRoot;
use miden_protocol::vm::AdviceMap;

use crate::errors::TransactionKernelError;

// CODE PATCH LIST
// ================================================================================================

/// The code patch lists into which the transaction kernel puts the procedure roots that it
/// verified.
///
/// The discriminants are the kinds of the lists in kernel memory, which are also the hint kinds
/// that the kernel reads (see `code_patch.masm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum CodePatchList {
    /// The procedure roots that are absent from the code tree.
    CreatedProcedures = 0,
    /// The present procedure roots that a created procedure references.
    Dependencies = 1,
    /// The present top-level procedure roots.
    PresentTopLevel = 2,
}

/// The hint kind with which the host requests that the kernel verifies the code witness of a
/// procedure root.
const NEW_WITNESS_HINT_KIND: u8 = 3;

// CODE PATCH TRACKER
// ================================================================================================

/// Answers the code witness verification requests of the transaction kernel.
///
/// The tracker mirrors the code patch lists that the kernel builds. For each procedure root that
/// the kernel verifies, it either gives the position of the root in one of the lists, so that the
/// kernel does not verify the same root twice, or provides the code witness of the root.
///
/// The advice stack layout is defined in `code_patch::verify_top_level_root` in the transaction
/// kernel.
#[derive(Debug)]
pub(crate) struct CodePatchTracker {
    /// The code tree of the reference block that tracks all available code witnesses.
    code_tree: PartialCodeTree,

    /// The position of each verified procedure root in the code patch lists.
    positions: BTreeMap<ProcedureRoot, (CodePatchList, u32)>,

    /// The number of procedure roots in each code patch list.
    list_lengths: BTreeMap<CodePatchList, u32>,
}

impl CodePatchTracker {
    /// Creates a new tracker that takes code witnesses from the provided code tree.
    pub fn new(code_tree: PartialCodeTree) -> Self {
        Self {
            code_tree,
            positions: BTreeMap::new(),
            list_lengths: BTreeMap::new(),
        }
    }

    /// Returns the code tree of the reference block.
    pub fn code_tree(&self) -> &PartialCodeTree {
        &self.code_tree
    }

    /// Returns `true` if the code witness of the procedure root is available.
    pub fn has_witness(&self, procedure_root: &ProcedureRoot) -> bool {
        self.code_tree.contains(procedure_root).is_ok()
    }

    /// Returns `true` if the kernel verified the procedure root before.
    pub fn is_verified(&self, procedure_root: &ProcedureRoot) -> bool {
        self.positions.contains_key(procedure_root)
    }

    /// Returns `true` if the procedure root is present in the code tree.
    ///
    /// # Errors
    ///
    /// Returns an error if the code witness of the procedure root is not available.
    pub fn is_present(
        &self,
        procedure_root: &ProcedureRoot,
    ) -> Result<bool, TransactionKernelError> {
        self.code_tree.contains(procedure_root).map_err(|source| {
            TransactionKernelError::MissingCodeWitness { procedure_root: *procedure_root, source }
        })
    }

    /// Adds the provided code witnesses to the available code witnesses.
    ///
    /// # Errors
    ///
    /// Returns an error if a witness does not fit the code tree of the reference block.
    pub fn add_witnesses(
        &mut self,
        witnesses: impl IntoIterator<Item = CodeWitness>,
    ) -> Result<(), TransactionKernelError> {
        for witness in witnesses {
            self.code_tree
                .track_procedure(witness)
                .map_err(TransactionKernelError::InvalidCodeWitness)?;
        }

        Ok(())
    }

    /// Returns `true` if the kernel must verify the procedures that the code of the top-level
    /// procedure root references, i.e. if it verifies the root for the first time and the root is
    /// absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the code witness of the procedure root is not available.
    pub fn needs_referenced_procedures(
        &self,
        procedure_root: &ProcedureRoot,
    ) -> Result<bool, TransactionKernelError> {
        Ok(!self.is_verified(procedure_root) && !self.is_present(procedure_root)?)
    }

    /// Builds the response to the verification of a top-level procedure root.
    ///
    /// `referenced_procedures` are the procedures that the code of the root references (see
    /// [`Self::needs_referenced_procedures`]).
    pub fn verify_top_level_root(
        &mut self,
        procedure_root: ProcedureRoot,
        referenced_procedures: Vec<ProcedureRoot>,
    ) -> Result<CodeRootVerification, TransactionKernelError> {
        let mut verification = CodeRootVerification::default();

        if let Some(&(list, index)) = self.positions.get(&procedure_root) {
            verification.push_hint(list as u8, index);
            return Ok(verification);
        }

        verification.push_witness(self.code_tree.open(&procedure_root).map_err(|source| {
            TransactionKernelError::MissingCodeWitness { procedure_root, source }
        })?)?;

        if self.is_present(&procedure_root)? {
            self.append(CodePatchList::PresentTopLevel, procedure_root);
            return Ok(verification);
        }

        self.append(CodePatchList::CreatedProcedures, procedure_root);

        verification.advice_stack.push(Felt::from(referenced_procedures.len() as u32));
        for referenced_root in referenced_procedures {
            verification.advice_stack.extend(referenced_root.as_word());
            self.verify_referenced_root(referenced_root, &mut verification)?;
        }

        Ok(verification)
    }

    /// Adds the response to the verification of a procedure root that a created procedure
    /// references.
    fn verify_referenced_root(
        &mut self,
        procedure_root: ProcedureRoot,
        verification: &mut CodeRootVerification,
    ) -> Result<(), TransactionKernelError> {
        if let Some(&(list, index)) = self.positions.get(&procedure_root) {
            verification.push_hint(list as u8, index);

            // The kernel puts a referenced root that is only known as a present top-level root
            // into the dependencies, so that the code patch commits to it.
            if list == CodePatchList::PresentTopLevel {
                self.append(CodePatchList::Dependencies, procedure_root);
            }

            return Ok(());
        }

        verification.push_witness(self.code_tree.open(&procedure_root).map_err(|source| {
            TransactionKernelError::MissingCodeWitness { procedure_root, source }
        })?)?;

        let list = if self.is_present(&procedure_root)? {
            CodePatchList::Dependencies
        } else {
            CodePatchList::CreatedProcedures
        };
        self.append(list, procedure_root);

        Ok(())
    }

    /// Mirrors the append of a procedure root to a code patch list in the kernel.
    fn append(&mut self, list: CodePatchList, procedure_root: ProcedureRoot) {
        let list_length = self.list_lengths.entry(list).or_default();
        self.positions.insert(procedure_root, (list, *list_length));
        *list_length += 1;
    }
}

// CODE ROOT VERIFICATION
// ================================================================================================

/// The response of the host to the verification of a top-level procedure root.
#[derive(Debug, Default)]
pub(crate) struct CodeRootVerification {
    /// The elements that the kernel reads from the advice stack.
    advice_stack: Vec<Felt>,
    /// The code witnesses that the kernel verifies.
    witnesses: Vec<CodeWitness>,
    /// The advice mutations that provide the code witnesses.
    witness_mutations: Vec<AdviceMutation>,
}

impl CodeRootVerification {
    /// Consumes the verification and returns its advice mutations and the code witnesses that the
    /// kernel verifies.
    pub fn into_parts(self) -> (Vec<AdviceMutation>, Vec<CodeWitness>) {
        let mut mutations = self.witness_mutations;
        mutations.push(AdviceMutation::extend_advice_stack_with(self.advice_stack));
        (mutations, self.witnesses)
    }

    /// Pushes a hint, which the kernel reads as `[hint_kind, index]`.
    fn push_hint(&mut self, hint_kind: u8, index: u32) {
        self.advice_stack.extend([Felt::from(index), Felt::from(hint_kind)]);
    }

    /// Pushes a hint that requests the verification of the provided code witness and provides
    /// the witness through the merkle store and the advice map.
    fn push_witness(&mut self, witness: CodeWitness) -> Result<(), TransactionKernelError> {
        self.push_hint(NEW_WITNESS_HINT_KIND, 0);

        let proof = witness.proof();
        let leaf = proof.leaf();
        let authenticated_nodes = proof
            .path()
            .authenticated_nodes(leaf.index().position(), leaf.hash())
            .map_err(|source| {
                TransactionKernelError::other_with_source(
                    "failed to compute the authenticated nodes of a code witness",
                    source,
                )
            })?;
        self.witness_mutations
            .push(AdviceMutation::extend_merkle_store(authenticated_nodes));
        self.witness_mutations.push(AdviceMutation::extend_map(AdviceMap::from_iter([(
            leaf.hash(),
            leaf.to_elements().collect::<Vec<_>>(),
        )])));
        self.witnesses.push(witness);

        Ok(())
    }
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

    /// Returns the advice stack of the verification, i.e. the elements that the kernel reads.
    fn advice_stack(verification: &CodeRootVerification) -> Vec<u64> {
        verification.advice_stack.iter().map(Felt::as_canonical_u64).collect()
    }

    /// Returns a hint as the kernel reads it from the advice stack.
    fn hint(list: CodePatchList, index: u64) -> [u64; 2] {
        [index, list as u64]
    }

    #[test]
    fn tracker_mirrors_the_code_patch_lists_of_the_kernel() -> anyhow::Result<()> {
        let present_root = ProcedureRoot::mock(0);
        let absent_root = ProcedureRoot::mock(1);
        let other_absent_root = ProcedureRoot::mock(2);
        let code_tree = CodeTree::with_entries([present_root])?;
        let mut tracker = CodePatchTracker::new(PartialCodeTree::with_witnesses(
            [present_root, absent_root, other_absent_root].map(|root| code_tree.open(&root)),
        )?);
        let new_witness_hint = [0, u64::from(NEW_WITNESS_HINT_KIND)];

        // A present top-level root goes into the present top-level list.
        let verification = tracker.verify_top_level_root(present_root, Vec::new())?;
        assert_eq!(advice_stack(&verification), new_witness_hint);
        assert_eq!(verification.witnesses, [code_tree.open(&present_root)]);

        // A repeated root is hinted.
        let verification = tracker.verify_top_level_root(present_root, Vec::new())?;
        assert_eq!(advice_stack(&verification), hint(CodePatchList::PresentTopLevel, 0));
        assert!(verification.witnesses.is_empty());

        // An absent top-level root that references the present top-level root moves the latter
        // into the dependencies.
        let verification = tracker.verify_top_level_root(absent_root, Vec::from([present_root]))?;
        let mut expected_stack = Vec::from(new_witness_hint);
        expected_stack.push(1);
        expected_stack.extend(present_root.as_word().iter().map(Felt::as_canonical_u64));
        expected_stack.extend(hint(CodePatchList::PresentTopLevel, 0));
        assert_eq!(advice_stack(&verification), expected_stack);

        // Afterwards, the reference is hinted with its position in the dependencies.
        let verification =
            tracker.verify_top_level_root(other_absent_root, Vec::from([present_root]))?;
        let mut expected_stack = Vec::from(new_witness_hint);
        expected_stack.push(1);
        expected_stack.extend(present_root.as_word().iter().map(Felt::as_canonical_u64));
        expected_stack.extend(hint(CodePatchList::Dependencies, 0));
        assert_eq!(advice_stack(&verification), expected_stack);

        // The absent roots are at the positions of the created procedures.
        let verification = tracker.verify_top_level_root(other_absent_root, Vec::new())?;
        assert_eq!(advice_stack(&verification), hint(CodePatchList::CreatedProcedures, 1));

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

    #[test]
    fn tracker_rejects_missing_witnesses_and_witnesses_of_other_trees() -> anyhow::Result<()> {
        let procedure_root = ProcedureRoot::mock(0);
        let code_tree = CodeTree::with_entries([procedure_root])?;
        let mut tracker = CodePatchTracker::new(PartialCodeTree::new(code_tree.root()));

        assert!(matches!(
            tracker.verify_top_level_root(procedure_root, Vec::new()),
            Err(TransactionKernelError::MissingCodeWitness { .. })
        ));

        let other_code_tree = CodeTree::with_entries([ProcedureRoot::mock(1)])?;
        assert!(matches!(
            tracker.add_witnesses([other_code_tree.open(&procedure_root)]),
            Err(TransactionKernelError::InvalidCodeWitness(_))
        ));

        Ok(())
    }
}
