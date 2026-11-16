use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use miden_processor::mast::{
    DenseMastForestBuilder,
    ExternalNodeBuilder,
    MastForest,
    MastForestError,
    MastNodeExt,
    MastNodeId,
    build_node_with_remapped_ids,
};
use miden_protocol::Word;

// PROCEDURE EXTRACTION
// ================================================================================================

/// Extracts the code of procedures from a [`MastForest`].
///
/// This only depends on the VM, so it can move to [`MastForest`] as is.
pub(crate) trait ExtractProcedures {
    /// Returns a forest with the code that the provided nodes reach.
    ///
    /// The provided nodes and each reached procedure root are procedure roots of the result. If
    /// `is_external` returns `true` for the digest of a reached procedure root, the procedure
    /// becomes an external node, and the extraction does not copy its code. The provided nodes are
    /// always copied. External nodes and dynamic nodes are leaves.
    ///
    /// Procedure roots with equal digests differ only in debug information, e.g. the messages of
    /// `assert.err`, which [`MastForest::merge`] keeps apart. The result contains only the first
    /// of them, so that each procedure is one procedure root or one external node.
    ///
    /// # Errors
    ///
    /// Returns an error if a provided node is not in the forest, or if the result is not a valid
    /// forest.
    fn extract_procedures(
        &self,
        roots: &[MastNodeId],
        is_external: impl Fn(Word) -> bool,
    ) -> Result<MastForest, MastForestError>;
}

/// The way a reached node goes into the extracted forest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtractedNode {
    /// The code of the node is copied.
    Code,
    /// The node becomes an external node.
    External,
    /// The node is a duplicate of the provided procedure root, and references to the node become
    /// references to that root.
    Duplicate(MastNodeId),
}

impl ExtractProcedures for MastForest {
    fn extract_procedures(
        &self,
        roots: &[MastNodeId],
        is_external: impl Fn(Word) -> bool,
    ) -> Result<MastForest, MastForestError> {
        // Find the nodes that the roots reach and decide for each one whether to copy its code.
        let extracted_nodes = reached_nodes(self, roots, is_external)?;

        // Copy the reached nodes into a new forest. The nodes of a forest are in topological
        // order, so the iteration in ascending order copies the children of a node before the
        // node, and each child already has its new ID.
        let mut forest_builder = DenseMastForestBuilder::new();
        let mut copied_nodes = BTreeMap::new();
        for (node_id, extracted_node) in extracted_nodes {
            let node = &self[node_id];
            let copied_node =
                match extracted_node {
                    ExtractedNode::Code => forest_builder.push_node(
                        build_node_with_remapped_ids(node_id, node.clone(), self, &copied_nodes)?,
                    )?,
                    ExtractedNode::External => {
                        forest_builder.push_node(ExternalNodeBuilder::new(node.digest()))?
                    },
                    // The first procedure root has a lower ID, so it is already copied.
                    ExtractedNode::Duplicate(procedure_root) => copied_nodes
                        .get(&procedure_root)
                        .copied()
                        .ok_or(MastForestError::ForwardReference(node_id, procedure_root))?,
                };

            // An external node only references a procedure, so it is not a procedure root.
            let is_root = roots.contains(&node_id) || self.is_procedure_root(node_id);
            if extracted_node == ExtractedNode::Code && is_root {
                forest_builder.mark_root(copied_node);
            }
            copied_nodes.insert(node_id, copied_node);
        }

        forest_builder.build()
    }
}

/// Returns the nodes that the provided nodes reach, without the code of external procedures.
fn reached_nodes(
    mast_forest: &MastForest,
    roots: &[MastNodeId],
    is_external: impl Fn(Word) -> bool,
) -> Result<BTreeMap<MastNodeId, ExtractedNode>, MastForestError> {
    let duplicate_roots = duplicate_procedure_roots(mast_forest);
    let mut extracted_nodes = BTreeMap::new();

    // Replaces a duplicate procedure root with the first procedure root of its digest.
    let deduplicate =
        |node_id: MastNodeId, extracted_nodes: &mut BTreeMap<MastNodeId, ExtractedNode>| {
            match duplicate_roots.get(&node_id) {
                Some(&procedure_root) => {
                    extracted_nodes.insert(node_id, ExtractedNode::Duplicate(procedure_root));
                    procedure_root
                },
                None => node_id,
            }
        };

    // The roots are always copied, also if `is_external` is `true` for their digest.
    let mut pending_nodes = Vec::new();
    for &root in roots {
        if mast_forest.get_node_by_id(root).is_none() {
            return Err(MastForestError::NodeIdOverflow(root, mast_forest.num_nodes() as usize));
        }
        let root = deduplicate(root, &mut extracted_nodes);
        extracted_nodes.insert(root, ExtractedNode::Code);
        pending_nodes.push(root);
    }

    // Visit each reached node once. The decision for a node depends only on the node, so the
    // visit order does not matter. The children of an external node are not visited, because its
    // code is not copied.
    let mut children = Vec::new();
    while let Some(node_id) = pending_nodes.pop() {
        mast_forest[node_id].append_children_to(&mut children);

        for child in children.drain(..) {
            let child = deduplicate(child, &mut extracted_nodes);
            if extracted_nodes.contains_key(&child) {
                continue;
            }

            let node = &mast_forest[child];
            let extracted_node = if node.is_external()
                || (mast_forest.is_procedure_root(child) && is_external(node.digest()))
            {
                ExtractedNode::External
            } else {
                ExtractedNode::Code
            };

            extracted_nodes.insert(child, extracted_node);
            if extracted_node == ExtractedNode::Code {
                pending_nodes.push(child);
            }
        }
    }

    Ok(extracted_nodes)
}

/// Returns each procedure root whose digest a procedure root with a lower ID has, mapped to the
/// procedure root with the lowest ID.
///
/// A parent has a higher ID than its children, so the first procedure root also has a lower ID
/// than each parent of a duplicate.
fn duplicate_procedure_roots(mast_forest: &MastForest) -> BTreeMap<MastNodeId, MastNodeId> {
    let procedure_roots = mast_forest.procedure_roots().iter().copied().collect::<BTreeSet<_>>();

    let mut first_roots = BTreeMap::new();
    let mut duplicate_roots = BTreeMap::new();
    for procedure_root in procedure_roots {
        match first_roots.entry(mast_forest[procedure_root].digest()) {
            Entry::Vacant(entry) => {
                entry.insert(procedure_root);
            },
            Entry::Occupied(entry) => {
                duplicate_roots.insert(procedure_root, *entry.get());
            },
        }
    }

    duplicate_roots
}
