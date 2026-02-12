use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::error::Error;

use miden_processor::{DeserializationError, ExecutionError};
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::assembly::diagnostics::reporting::PrintDiagnostic;
use miden_protocol::asset::AssetVaultKey;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::smt::SmtProofError;
use miden_protocol::errors::{
    AccountDeltaError,
    AccountError,
    AssetError,
    NoteError,
    ProvenTransactionError,
    TransactionInputError,
    TransactionInputsExtractionError,
    TransactionOutputError,
};
use miden_protocol::note::{NoteId, NoteMetadata};
use miden_protocol::transaction::TransactionSummary;
use miden_protocol::{Felt, Word};
use miden_verifier::VerificationError;
use thiserror::Error;

// NOTE EXECUTION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NoteCheckerError {
    #[error("invalid input note count {0} is out of range)")]
    InputNoteCountOutOfRange(usize),
    #[error("transaction preparation failed: {0}")]
    TransactionPreparation(#[source] TransactionExecutorError),
    #[error("transaction execution prologue failed: {0}")]
    PrologueExecution(#[source] TransactionExecutorError),
}

// TRANSACTION CHECKER ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub(crate) enum TransactionCheckerError {
    #[error("transaction preparation failed: {0}")]
    TransactionPreparation(#[source] TransactionExecutorError),
    #[error("transaction execution prologue failed: {0}")]
    PrologueExecution(#[source] TransactionExecutorError),
    #[error("transaction execution epilogue failed: {0}")]
    EpilogueExecution(#[source] TransactionExecutorError),
    #[error("transaction note execution failed on note index {failed_note_index}: {error}")]
    NoteExecution {
        failed_note_index: usize,
        error: TransactionExecutorError,
    },
}

impl From<TransactionCheckerError> for TransactionExecutorError {
    fn from(error: TransactionCheckerError) -> Self {
        match error {
            TransactionCheckerError::TransactionPreparation(error) => error,
            TransactionCheckerError::PrologueExecution(error) => error,
            TransactionCheckerError::EpilogueExecution(error) => error,
            TransactionCheckerError::NoteExecution { error, .. } => error,
        }
    }
}

// TRANSACTION EXECUTOR ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionExecutorError {
    #[error("failed to read fee asset from transaction inputs")]
    FeeAssetRetrievalFailed(#[source] TransactionInputsExtractionError),
    #[error("failed to fetch transaction inputs from the data store")]
    FetchTransactionInputsFailed(#[source] DataStoreError),
    #[error("failed to fetch asset witnesses from the data store")]
    FetchAssetWitnessFailed(#[source] DataStoreError),
    #[error("fee asset must be fungible but was non-fungible")]
    FeeAssetMustBeFungible,
    #[error("foreign account inputs for ID {0} are not anchored on reference block")]
    ForeignAccountNotAnchoredInReference(AccountId),
    #[error(
        "execution options' cycles must be between {min_cycles} and {max_cycles}, but found {actual}"
    )]
    InvalidExecutionOptionsCycles {
        min_cycles: u32,
        max_cycles: u32,
        actual: u32,
    },
    #[error("failed to create transaction inputs")]
    InvalidTransactionInputs(#[source] TransactionInputError),
    #[error("failed to process account update commitment: {0}")]
    AccountUpdateCommitment(&'static str),
    #[error(
        "account delta commitment computed in transaction kernel ({in_kernel_commitment}) does not match account delta computed via the host ({host_commitment})"
    )]
    InconsistentAccountDeltaCommitment {
        in_kernel_commitment: Word,
        host_commitment: Word,
    },
    #[error("failed to remove the fee asset from the pre-fee account delta")]
    RemoveFeeAssetFromDelta(#[source] AccountDeltaError),
    #[error("input account ID {input_id} does not match output account ID {output_id}")]
    InconsistentAccountId {
        input_id: AccountId,
        output_id: AccountId,
    },
    #[error("expected account nonce delta to be {expected}, found {actual}")]
    InconsistentAccountNonceDelta { expected: Felt, actual: Felt },
    #[error(
        "native asset amount {account_balance} in the account vault is not sufficient to cover the transaction fee of {tx_fee}"
    )]
    InsufficientFee { account_balance: u64, tx_fee: u64 },
    #[error("account witness provided for account ID {0} is invalid")]
    InvalidAccountWitness(AccountId, #[source] SmtProofError),
    #[error(
        "input note {0} was created in a block past the transaction reference block number ({1})"
    )]
    NoteBlockPastReferenceBlock(NoteId, BlockNumber),
    #[error("failed to construct transaction outputs")]
    TransactionOutputConstructionFailed(#[source] TransactionOutputError),
    // Print the diagnostic directly instead of returning the source error. In the source error
    // case, the diagnostic is lost if the execution error is not explicitly unwrapped.
    #[error("failed to execute transaction kernel program:\n{}", PrintDiagnostic::new(.0))]
    TransactionProgramExecutionFailed(ExecutionError),
    /// This variant can be matched on to get the summary of a transaction for signing purposes.
    // It is boxed to avoid triggering clippy::result_large_err for functions that return this type.
    #[error("transaction is unauthorized with summary {0:?}")]
    Unauthorized(Box<TransactionSummary>),
    #[error(
        "failed to respond to signature requested since no authenticator is assigned to the host"
    )]
    MissingAuthenticator,
}

// TRANSACTION PROVER ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionProverError {
    #[error("failed to apply account delta")]
    AccountDeltaApplyFailed(#[source] AccountError),
    #[error("failed to remove the fee asset from the pre-fee account delta")]
    RemoveFeeAssetFromDelta(#[source] AccountDeltaError),
    #[error("failed to construct transaction outputs")]
    TransactionOutputConstructionFailed(#[source] TransactionOutputError),
    #[error("failed to build proven transaction")]
    ProvenTransactionBuildFailed(#[source] ProvenTransactionError),
    // Print the diagnostic directly instead of returning the source error. In the source error
    // case, the diagnostic is lost if the execution error is not explicitly unwrapped.
    #[error("failed to execute transaction kernel program:\n{}", PrintDiagnostic::new(.0))]
    TransactionProgramExecutionFailed(ExecutionError),
    /// Custom error variant for errors not covered by the other variants.
    #[error("{error_msg}")]
    Other {
        error_msg: Box<str>,
        // thiserror will return this when calling Error::source on DataStoreError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
}

impl TransactionProverError {
    /// Creates a custom error using the [`TransactionProverError::Other`] variant from an error
    /// message.
    pub fn other(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::Other { error_msg: message.into(), source: None }
    }

    /// Creates a custom error using the [`TransactionProverError::Other`] variant from an error
    /// message and a source error.
    pub fn other_with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message: String = message.into();
        Self::Other {
            error_msg: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

// TRANSACTION VERIFIER ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionVerifierError {
    #[error("failed to verify transaction")]
    TransactionVerificationFailed(#[source] VerificationError),
    #[error("transaction proof security level is {actual} but must be at least {expected_minimum}")]
    InsufficientProofSecurityLevel { actual: u32, expected_minimum: u32 },
}

// TRANSACTION KERNEL ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionKernelError {
    #[error("failed to add asset to account delta")]
    AccountDeltaAddAssetFailed(#[source] AccountDeltaError),
    #[error("failed to remove asset from account delta")]
    AccountDeltaRemoveAssetFailed(#[source] AccountDeltaError),
    #[error("failed to add asset to note")]
    FailedToAddAssetToNote(#[source] NoteError),
    #[error("note storage has commitment {actual} but expected commitment {expected}")]
    InvalidNoteStorage { expected: Word, actual: Word },
    #[error(
        "failed to respond to signature requested since no authenticator is assigned to the host"
    )]
    MissingAuthenticator,
    #[error("failed to generate signature")]
    SignatureGenerationFailed(#[source] AuthenticationError),
    #[error("transaction returned unauthorized event but a commitment did not match: {0}")]
    TransactionSummaryCommitmentMismatch(#[source] Box<dyn Error + Send + Sync + 'static>),
    #[error("failed to construct transaction summary")]
    TransactionSummaryConstructionFailed(#[source] Box<dyn Error + Send + Sync + 'static>),
    #[error("asset data extracted from the stack by event handler `{handler}` is not well formed")]
    MalformedAssetInEventHandler {
        handler: &'static str,
        source: AssetError,
    },
    #[error(
        "note storage data extracted from the advice map by the event handler is not well formed"
    )]
    MalformedNoteStorage(#[source] NoteError),
    #[error(
        "note script data `{data:?}` extracted from the advice map by the event handler is not well formed"
    )]
    MalformedNoteScript {
        data: Vec<Felt>,
        source: DeserializationError,
    },
    #[error("recipient data `{0:?}` in the advice provider is not well formed")]
    MalformedRecipientData(Vec<Felt>),
    #[error("cannot add asset to note with index {0}, note does not exist in the advice provider")]
    MissingNote(usize),
    #[error(
        "public note with metadata {0:?} and recipient digest {1} is missing details in the advice provider"
    )]
    PublicNoteMissingDetails(NoteMetadata, Word),
    #[error("attachment provided to set_attachment must be empty when attachment kind is None")]
    NoteAttachmentNoneIsNotEmpty,
    #[error(
        "commitment of note attachment {actual} does not match attachment {provided} provided to set_attachment"
    )]
    NoteAttachmentArrayMismatch { actual: Word, provided: Word },
    #[error(
        "note storage in advice provider contains fewer items ({actual}) than specified ({specified}) by its number of storage items"
    )]
    TooFewElementsForNoteStorage { specified: u64, actual: u64 },
    #[error("account procedure with procedure root {0} is not in the account procedure index map")]
    UnknownAccountProcedure(Word),
    #[error("code commitment {0} is not in the account procedure index map")]
    UnknownCodeCommitment(Word),
    #[error("account storage slots number is missing in memory at address {0}")]
    AccountStorageSlotsNumMissing(u32),
    #[error("account nonce can only be incremented once")]
    NonceCanOnlyIncrementOnce,
    #[error("failed to convert fee asset into fungible asset")]
    FailedToConvertFeeAsset(#[source] AssetError),
    #[error(
        "failed to get inputs for foreign account {foreign_account_id} from data store at reference block {ref_block}"
    )]
    GetForeignAccountInputs {
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
        // thiserror will return this when calling Error::source on TransactionKernelError.
        source: DataStoreError,
    },
    #[error(
        "failed to get vault asset witness from data store for vault root {vault_root} and vault_key {asset_key}"
    )]
    GetVaultAssetWitness {
        vault_root: Word,
        asset_key: AssetVaultKey,
        // thiserror will return this when calling Error::source on TransactionKernelError.
        source: DataStoreError,
    },
    #[error(
        "failed to get storage map witness from data store for map root {map_root} and map_key {map_key}"
    )]
    GetStorageMapWitness {
        map_root: Word,
        map_key: Word,
        // thiserror will return this when calling Error::source on TransactionKernelError.
        source: DataStoreError,
    },
    #[error(
        "native asset amount {account_balance} in the account vault is not sufficient to cover the transaction fee of {tx_fee}"
    )]
    InsufficientFee { account_balance: u64, tx_fee: u64 },
    /// This variant signals that a signature over the contained commitments is required, but
    /// missing.
    #[error("transaction requires a signature")]
    Unauthorized(Box<TransactionSummary>),
    /// A generic error returned when the transaction kernel did not behave as expected.
    #[error("{message}")]
    Other {
        message: Box<str>,
        // thiserror will return this when calling Error::source on TransactionKernelError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
}

impl TransactionKernelError {
    /// Creates a custom error using the [`TransactionKernelError::Other`] variant from an error
    /// message.
    pub fn other(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::Other { message: message.into(), source: None }
    }

    /// Creates a custom error using the [`TransactionKernelError::Other`] variant from an error
    /// message and a source error.
    pub fn other_with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message: String = message.into();
        Self::Other {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

// DATA STORE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum DataStoreError {
    #[error("account with id {0} not found in data store")]
    AccountNotFound(AccountId),
    #[error("block with number {0} not found in data store")]
    BlockNotFound(BlockNumber),
    /// Custom error variant for implementors of the [`DataStore`](crate::executor::DataStore)
    /// trait.
    #[error("{error_msg}")]
    Other {
        error_msg: Box<str>,
        // thiserror will return this when calling Error::source on DataStoreError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
}

impl DataStoreError {
    /// Creates a custom error using the [`DataStoreError::Other`] variant from an error message.
    pub fn other(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::Other { error_msg: message.into(), source: None }
    }

    /// Creates a custom error using the [`DataStoreError::Other`] variant from an error message and
    /// a source error.
    pub fn other_with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message: String = message.into();
        Self::Other {
            error_msg: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

// AUTHENTICATION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("signature rejected: {0}")]
    RejectedSignature(String),
    #[error("public key `{0}` is not contained in the authenticator's keys")]
    UnknownPublicKey(PublicKeyCommitment),
    /// Custom error variant for implementors of the
    /// [`TransactionAuthenticator`](crate::auth::TransactionAuthenticator) trait.
    #[error("{error_msg}")]
    Other {
        error_msg: Box<str>,
        // thiserror will return this when calling Error::source on DataStoreError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
}

impl AuthenticationError {
    /// Creates a custom error using the [`AuthenticationError::Other`] variant from an error
    /// message.
    pub fn other(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::Other { error_msg: message.into(), source: None }
    }

    /// Creates a custom error using the [`AuthenticationError::Other`] variant from an error
    /// message and a source error.
    pub fn other_with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message: String = message.into();
        Self::Other {
            error_msg: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

#[cfg(test)]
mod error_assertions {
    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_data_store_error_bounds(err: DataStoreError) {
        _assert_error_is_send_sync_static(err);
    }

    fn _assert_authentication_error_bounds(err: AuthenticationError) {
        _assert_error_is_send_sync_static(err);
    }

    fn _assert_transaction_kernel_error_bounds(err: TransactionKernelError) {
        _assert_error_is_send_sync_static(err);
    }
}
