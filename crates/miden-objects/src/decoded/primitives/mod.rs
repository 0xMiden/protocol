//! Domain construction for decoded primitives messages.

#[cfg(test)]
pub(crate) mod test_utils;

mod merkle;
pub use merkle::{MerklePath, MmrDelta, SparseMerklePath};

mod smt;
pub use smt::{
    IndexedDigest,
    IndexedSmtLeaf,
    PartialSmt,
    PartialSmtError,
    PartialSmtNode,
    PartialSmtNodeLevel,
    SmtLeaf,
    SmtLeafEntry,
    SmtLeafEntryList,
    SmtOpening,
};

mod advice;
pub use advice::{
    AdviceError,
    AdviceInputs,
    AdviceMap,
    AdviceMapEntry,
    AdviceStack,
    MerkleStore,
    MerkleStoreNode,
};

mod mast;
pub use mast::{MastForest, UntrustedMastForest};

mod crypto;
pub use crypto::{Canonical, PublicKey, Signature};
