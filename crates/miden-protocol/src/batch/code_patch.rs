use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use core::fmt::Display;

use miden_crypto_derive::WordWrapper;

use crate::block::code_tree::{CodePatch, CodePatchKind};
use crate::code::ProcedureRoot;
use crate::domain_registry::{BATCH_CODE_PATCH_COMMITMENT_DOMAIN, BatchCodePatchCommitmentDomain};
use crate::errors::CodePatchError;
use crate::transaction::TransactionCodePatch;
use crate::{MastForest, Word};

// BATCH CODE PATCH
// ================================================================================================

/// The merged code patch of the transactions of a batch.
///
/// It has the invariants of a [`TransactionCodePatch`], but its own limits, because it contains
/// the code of many transactions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchCodePatch(CodePatch<BatchCodePatch>);

impl BatchCodePatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum size of a serialized patch in bytes (2 MiB).
    pub const MAX_SIZE: u32 = 2u32.pow(21);

    /// The maximum number of procedure roots in each list of a patch.
    pub const MAX_ROOTS: usize = 4096;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BatchCodePatch`] from the MAST forest of the created procedures.
    ///
    /// # Errors
    ///
    /// Returns an error if the forest is not a valid patch (see [`TransactionCodePatch::new`]) for
    /// the limits [`Self::MAX_ROOTS`] and [`Self::MAX_SIZE`].
    pub fn new(mast: Arc<MastForest>) -> Result<Self, CodePatchError> {
        CodePatch::new(mast).map(Self)
    }

    /// Merges the patches of the transactions of a batch into one patch.
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
    pub fn merge<'patch>(
        patches: impl IntoIterator<Item = &'patch TransactionCodePatch>,
    ) -> Result<Self, CodePatchError> {
        CodePatch::merge(patches.into_iter().map(TransactionCodePatch::as_core)).map(Self)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the MAST forest containing the created procedures.
    pub fn mast(&self) -> &Arc<MastForest> {
        self.0.mast()
    }

    /// Returns the set of created procedure roots.
    pub fn created_procedures(&self) -> BTreeSet<ProcedureRoot> {
        self.0.created_procedures()
    }

    /// Returns the set of dependencies.
    pub fn dependencies(&self) -> BTreeSet<ProcedureRoot> {
        self.0.dependencies()
    }

    /// Returns `true` if the patch creates no procedures.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the commitment to the created procedures.
    pub fn created_commitment(&self) -> Word {
        self.0.created_commitment()
    }

    /// Returns the commitment to the dependencies.
    pub fn dependencies_commitment(&self) -> Word {
        self.0.dependencies_commitment()
    }

    /// Returns the commitment to this patch.
    ///
    /// The commitment is the merge of [`Self::created_commitment`] and
    /// [`Self::dependencies_commitment`] in the domain of batch code patches.
    pub fn commitment(&self) -> BatchCodePatchCommitment {
        BatchCodePatchCommitment::from_raw(self.0.commitment())
    }

    /// Returns the shared code patch implementation.
    pub(crate) fn as_core(&self) -> &CodePatch<BatchCodePatch> {
        &self.0
    }
}

impl CodePatchKind for BatchCodePatch {
    type CommitmentDomain = BatchCodePatchCommitmentDomain;

    const COMMITMENT_DOMAIN: Self::CommitmentDomain = BATCH_CODE_PATCH_COMMITMENT_DOMAIN;
    const MAX_SIZE: u32 = BatchCodePatch::MAX_SIZE;
    const MAX_ROOTS: usize = BatchCodePatch::MAX_ROOTS;
}

// BATCH CODE PATCH COMMITMENT
// ================================================================================================

/// The commitment to a [`BatchCodePatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, WordWrapper)]
pub struct BatchCodePatchCommitment(Word);

impl Display for BatchCodePatchCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_word())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::mast::{BasicBlockNodeBuilder, MastNode, MastNodeId};
    use miden_core::operations::Operation;

    use super::*;
    use crate::Felt;
    use crate::utils::IndexVec;
    use crate::vm::AdviceMap;

    /// Returns a transaction patch whose created procedures are the basic blocks `push.value` of
    /// the values.
    fn push_block_patch(
        values: impl IntoIterator<Item = u32>,
    ) -> anyhow::Result<TransactionCodePatch> {
        let mut nodes: IndexVec<MastNodeId, MastNode> = IndexVec::new();
        let mut roots = Vec::new();
        for value in values {
            let block =
                BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(value))]).build()?;
            roots.push(nodes.push(block.into())?);
        }
        let mast = MastForest::from_raw_parts(nodes, roots, AdviceMap::default())?;

        Ok(TransactionCodePatch::new(Arc::new(mast))?)
    }

    /// The batch patch can contain more procedures than a single transaction patch, and its
    /// commitment is in its own domain.
    #[test]
    fn merge_exceeds_transaction_limits() -> anyhow::Result<()> {
        let max_roots = u32::try_from(TransactionCodePatch::MAX_ROOTS)?;
        let first_patch = push_block_patch(0..max_roots)?;
        let second_patch = push_block_patch(max_roots..2 * max_roots)?;

        let batch_patch = BatchCodePatch::merge([&first_patch, &second_patch])?;

        assert_eq!(batch_patch.created_procedures().len(), 2 * TransactionCodePatch::MAX_ROOTS);
        assert_ne!(
            BatchCodePatch::merge([&first_patch])?.commitment().as_word(),
            first_patch.commitment().as_word()
        );

        Ok(())
    }
}
