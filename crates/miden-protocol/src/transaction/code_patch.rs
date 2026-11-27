use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use core::fmt::Display;

use miden_crypto_derive::WordWrapper;

use crate::block::code_tree::{CodePatch, CodePatchKind};
use crate::code::ProcedureRoot;
use crate::domain_registry::{
    TRANSACTION_CODE_PATCH_COMMITMENT_DOMAIN,
    TransactionCodePatchCommitmentDomain,
};
use crate::errors::CodePatchError;
use crate::{MastForest, Word};

// TRANSACTION CODE PATCH
// ================================================================================================

/// The procedures a transaction creates, i.e. the code it adds to the
/// [`CodeTree`](crate::block::code_tree::CodeTree) and its code registry, and the procedures it
/// depends on.
///
/// The created procedures are the procedure roots of the contained [`MastForest`]. The
/// dependencies are the procedures that the external nodes of the forest reference and that the
/// transaction proves present in the code tree. A present top-level root, e.g. a note script root,
/// is a dependency only if a created procedure references it.
///
/// Both lists are sorted, so their commitments are the interface and dependency commitments of the
/// forest and are equal to the commitments over the strictly sorted lists of the transaction
/// kernel. Hence, the procedure roots and the external nodes must each be unique, since a duplicate
/// would make the forest commitments differ from the kernel's.
///
/// A dependency must not be a created procedure, i.e. an external node must not reference a
/// created procedure. Building the forest with [`MastForest::merge`] replaces such references with
/// the procedure itself. This rejects a procedure root that is a single external node, which would
/// register a reference instead of code. It does not prevent a host from making an inner node of a
/// created procedure a separate root, which adds a code tree entry that the account pays for.
///
/// Every node of the forest must be reachable from a created procedure. The commitments do not
/// cover the code of unreachable nodes, so they could add arbitrary data to the registry without
/// changing the commitment.
///
/// The advice map of the forest must be empty. Advice is expected to be removed from
/// [`MastForest`], so the code tree and its registry do not commit to or store it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionCodePatch(CodePatch<TransactionCodePatch>);

impl TransactionCodePatch {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum size of a serialized patch in bytes (256 KiB).
    pub const MAX_SIZE: u32 = 2u32.pow(18);

    /// The maximum number of procedure roots in each list of a patch.
    pub const MAX_ROOTS: usize = 512;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TransactionCodePatch`] from the MAST forest of the created procedures.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the number of procedure roots or external nodes of the forest exceeds [`Self::MAX_ROOTS`].
    /// - a procedure root or an external node digest of the forest is duplicated.
    /// - an external node references a procedure root of the forest.
    /// - a node of the forest is not reachable from a procedure root.
    /// - the advice map of the forest is not empty.
    /// - the serialized forest exceeds [`Self::MAX_SIZE`].
    pub fn new(mast: Arc<MastForest>) -> Result<Self, CodePatchError> {
        CodePatch::new(mast).map(Self)
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
    ///
    /// Such a patch has no dependencies either, since every node is reachable from a created
    /// procedure.
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
    /// [`Self::dependencies_commitment`] in the domain of transaction code patches.
    pub fn commitment(&self) -> TransactionCodePatchCommitment {
        TransactionCodePatchCommitment::from_raw(self.0.commitment())
    }

    /// Returns the shared code patch implementation.
    pub(crate) fn as_core(&self) -> &CodePatch<TransactionCodePatch> {
        &self.0
    }
}

impl CodePatchKind for TransactionCodePatch {
    type CommitmentDomain = TransactionCodePatchCommitmentDomain;

    const COMMITMENT_DOMAIN: Self::CommitmentDomain = TRANSACTION_CODE_PATCH_COMMITMENT_DOMAIN;
    const MAX_SIZE: u32 = TransactionCodePatch::MAX_SIZE;
    const MAX_ROOTS: usize = TransactionCodePatch::MAX_ROOTS;
}

// TRANSACTION CODE PATCH COMMITMENT
// ================================================================================================

/// The commitment to a [`TransactionCodePatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, WordWrapper)]
pub struct TransactionCodePatchCommitment(Word);

impl Display for TransactionCodePatchCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_word())
    }
}
