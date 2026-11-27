use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use core::fmt::Display;

use miden_crypto_derive::WordWrapper;

use crate::batch::BatchCodePatch;
use crate::block::code_tree::{CodePatch, CodePatchKind};
use crate::code::ProcedureRoot;
use crate::domain_registry::{BLOCK_CODE_PATCH_COMMITMENT_DOMAIN, BlockCodePatchCommitmentDomain};
use crate::errors::CodePatchError;
use crate::{MastForest, Word};

// BLOCK CODE PATCH
// ================================================================================================

/// The merged code patch of the batches of a block.
///
/// It has the invariants of a [`TransactionCodePatch`](crate::transaction::TransactionCodePatch),
/// but its own limits, because it contains the code of many batches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockCodePatch(CodePatch<BlockCodePatch>);

impl BlockCodePatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum size of a serialized patch in bytes (2 MiB).
    pub const MAX_SIZE: u32 = 2u32.pow(21);

    /// The maximum number of procedure roots in each list of a patch.
    pub const MAX_ROOTS: usize = 4096;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BlockCodePatch`] from the MAST forest of the created procedures.
    ///
    /// # Errors
    ///
    /// Returns an error if the forest is not a valid patch (see [`BatchCodePatch::new`]) for the
    /// limits [`Self::MAX_ROOTS`] and [`Self::MAX_SIZE`].
    pub fn new(mast: Arc<MastForest>) -> Result<Self, CodePatchError> {
        CodePatch::new(mast).map(Self)
    }

    /// Merges the patches of the batches of a block into one patch.
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
        patches: impl IntoIterator<Item = &'patch BatchCodePatch>,
    ) -> Result<Self, CodePatchError> {
        CodePatch::merge(patches.into_iter().map(BatchCodePatch::as_core)).map(Self)
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
    /// [`Self::dependencies_commitment`] in the domain of block code patches.
    pub fn commitment(&self) -> BlockCodePatchCommitment {
        BlockCodePatchCommitment::from_raw(self.0.commitment())
    }
}

impl CodePatchKind for BlockCodePatch {
    type CommitmentDomain = BlockCodePatchCommitmentDomain;

    const COMMITMENT_DOMAIN: Self::CommitmentDomain = BLOCK_CODE_PATCH_COMMITMENT_DOMAIN;
    const MAX_SIZE: u32 = BlockCodePatch::MAX_SIZE;
    const MAX_ROOTS: usize = BlockCodePatch::MAX_ROOTS;
}

// BLOCK CODE PATCH COMMITMENT
// ================================================================================================

/// The commitment to a [`BlockCodePatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, WordWrapper)]
pub struct BlockCodePatchCommitment(Word);

impl Display for BlockCodePatchCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_word())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TransactionCodePatch;

    /// The commitment of the block patch is in its own domain.
    #[test]
    fn commitment_is_in_block_domain() -> anyhow::Result<()> {
        let batch_patch = BatchCodePatch::merge([&TransactionCodePatch::mock()])?;

        let block_patch = BlockCodePatch::merge([&batch_patch])?;

        assert_eq!(block_patch.created_procedures(), batch_patch.created_procedures());
        assert_ne!(block_patch.commitment().as_word(), batch_patch.commitment().as_word());

        Ok(())
    }
}
