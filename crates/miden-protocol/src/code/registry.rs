use alloc::collections::BTreeSet;
use alloc::sync::Arc;

use miden_processor::{LoadedMastForest, MastForestStore};

use crate::block::BlockCodePatch;
use crate::code::ProcedureRoot;
use crate::errors::CodeRegistryError;
use crate::{MastForest, Word};

// CODE REGISTRY
// ================================================================================================

/// The code of all procedure roots registered in the blockchain.
///
/// The registry is kept in sync with the [`CodeTree`](crate::block::code_tree::CodeTree), so that
/// every procedure that the tree tracks can be resolved. It is one [`MastForest`], so that code
/// that more than one block registers is stored once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRegistry {
    mast: Arc<MastForest>,
}

impl CodeRegistry {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`CodeRegistry`] from the MAST forest of the registered code.
    pub fn new(mast: Arc<MastForest>) -> Self {
        Self { mast }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the MAST forest of the registered code.
    pub fn mast(&self) -> &Arc<MastForest> {
        &self.mast
    }

    /// Returns the set of registered procedure roots.
    pub fn procedure_roots(&self) -> BTreeSet<ProcedureRoot> {
        self.mast.local_procedure_digests().map(ProcedureRoot::from_raw).collect()
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Merges the code of the patch into this registry.
    ///
    /// An empty patch skips the merge, which rebuilds the whole forest.
    ///
    /// # Errors
    ///
    /// Returns an error if the forests cannot be merged.
    pub fn merge_patch(&mut self, patch: &BlockCodePatch) -> Result<(), CodeRegistryError> {
        if patch.is_empty() {
            return Ok(());
        }

        let (mast, _) = MastForest::merge([self.mast.as_ref(), patch.mast().as_ref()])
            .map_err(CodeRegistryError::MastForestMerge)?;
        self.mast = Arc::new(mast);

        Ok(())
    }
}

// MAST FOREST STORE IMPLEMENTATION
// ================================================================================================

impl MastForestStore for CodeRegistry {
    fn get(&self, procedure_root: &Word) -> Option<LoadedMastForest> {
        let node_id = self.mast.find_procedure_root(*procedure_root)?;
        if self.mast[node_id].is_external() {
            return None;
        }

        Some(LoadedMastForest::new(Arc::clone(&self.mast)))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::BatchCodePatch;
    use crate::transaction::TransactionCodePatch;

    fn mock_block_patch() -> anyhow::Result<BlockCodePatch> {
        let batch_patch = BatchCodePatch::merge([&TransactionCodePatch::mock()])?;
        Ok(BlockCodePatch::merge([&batch_patch])?)
    }

    /// The created procedures of a merged patch are registered, but its dependencies are not.
    #[test]
    fn merge_patch_registers_created_procedures() -> anyhow::Result<()> {
        let patch = mock_block_patch()?;
        let mut registry = CodeRegistry::new(Arc::new(MastForest::new()));

        registry.merge_patch(&patch)?;

        assert_eq!(registry.procedure_roots(), patch.created_procedures());
        for procedure_root in patch.created_procedures() {
            assert!(registry.get(&procedure_root.as_word()).is_some());
        }
        for dependency in patch.dependencies() {
            assert!(registry.get(&dependency.as_word()).is_none());
        }

        Ok(())
    }

    /// An empty patch does not rebuild the forest.
    #[test]
    fn merge_of_empty_patch_keeps_forest() -> anyhow::Result<()> {
        let mut registry = CodeRegistry::new(Arc::clone(mock_block_patch()?.mast()));
        let mast = Arc::clone(registry.mast());

        registry.merge_patch(&BlockCodePatch::default())?;

        assert!(Arc::ptr_eq(registry.mast(), &mast));

        Ok(())
    }
}
