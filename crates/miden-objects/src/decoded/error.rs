use alloc::boxed::Box;
use core::error::Error;

#[cfg(test)]
mod tests;

/// A verification failure from a composite object, preserving its concrete domain source.
///
/// Nested verifiers propagate this wrapper unchanged instead of introducing an error enum at
/// every layer. Inspect [`Error::source`] to distinguish domain failures or the invariant errors
/// defined alongside individual verifiers. Unlike structural decoding errors, these errors do
/// not have generated wire paths.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct VerificationError(#[source] Box<dyn Error + Send + Sync>);

impl VerificationError {
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        let source: Box<dyn Error + Send + Sync> = Box::new(source);
        match source.downcast::<Self>() {
            Ok(error) => *error,
            Err(source) => Self(source),
        }
    }
}

macro_rules! impl_verification_error_from {
    ($($ty:ty),* $(,)?) => {$(
        impl From<$ty> for VerificationError {
            fn from(error: $ty) -> Self {
                Self::new(error)
            }
        }
    )*};
}

impl_verification_error_from!(
    core::num::TryFromIntError,
    miden_protocol::assembly::mast::MastForestError,
    miden_protocol::block::SignedBlockError,
    miden_protocol::crypto::merkle::MerkleError,
    miden_protocol::crypto::merkle::mmr::MmrError,
    miden_protocol::crypto::merkle::smt::SmtLeafError,
    miden_protocol::crypto::merkle::smt::SmtProofError,
    miden_protocol::errors::AccountError,
    miden_protocol::errors::AccountIdError,
    miden_protocol::errors::AccountPatchError,
    miden_protocol::errors::AccountTreeError,
    miden_protocol::errors::AssetError,
    miden_protocol::errors::BatchAccountUpdateError,
    miden_protocol::errors::BlockAccountUpdateError,
    miden_protocol::errors::BlockBodyError,
    miden_protocol::errors::NoteError,
    miden_protocol::errors::OutputNoteError,
    miden_protocol::errors::PartialAssetVaultError,
    miden_protocol::errors::PartialBlockchainError,
    miden_protocol::errors::ProposedBatchError,
    miden_protocol::errors::ProtocolConfigError,
    miden_protocol::errors::ProvenBatchError,
    miden_protocol::errors::ProvenTransactionError,
    miden_protocol::errors::StorageSlotNameError,
    miden_protocol::errors::TransactionHeaderError,
    miden_protocol::errors::TransactionInputError,
    miden_protocol::errors::ValidatorConfigError,
    miden_protocol::utils::serde::DeserializationError,
    super::account::AccountHeaderError,
    super::account::AccountPatchError,
    super::account::PartialStorageError,
    super::account::StorageMapPatchError,
    super::account::VaultPatchError,
    super::asset::AssetIdError,
    super::blockchain::BlockHeaderError,
    super::blockchain::PartialBlockchainError,
    super::note::NoteMetadataError,
    super::primitives::AdviceError,
    super::primitives::PartialSmtError,
    super::transaction::ForeignAccountSlotNameError,
    super::transaction::InputNoteError,
    super::transaction::ProposedBatchError,
    super::transaction::ProvenBatchError,
    super::transaction::TransactionArgsError,
    super::transaction::TransactionHeaderBuildError,
    super::transaction::TransactionInputsError,
);
