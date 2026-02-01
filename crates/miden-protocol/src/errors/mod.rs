use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::error::Error;

use miden_assembly::Report;
use miden_assembly::diagnostics::reporting::PrintDiagnostic;
use miden_core::mast::MastForestError;
use miden_core::{EventId, Felt};
use miden_crypto::merkle::mmr::MmrError;
use miden_crypto::merkle::smt::{SmtLeafError, SmtProofError};
use miden_crypto::utils::HexParseError;
use miden_processor::DeserializationError;
use thiserror::Error;

use super::account::AccountId;
use super::asset::{FungibleAsset, NonFungibleAsset, TokenSymbol};
use super::crypto::merkle::MerkleError;
use super::note::NoteId;
use super::{MAX_BATCHES_PER_BLOCK, MAX_OUTPUT_NOTES_PER_BATCH, Word};
use crate::account::component::{SchemaTypeError, StorageValueName, StorageValueNameError};
use crate::account::{
    AccountCode,
    AccountIdPrefix,
    AccountStorage,
    AccountType,
    StorageSlotId,
    // StorageValueName,
    // StorageValueNameError,
    // TemplateTypeError,
    StorageSlotName,
};
use crate::address::AddressType;
use crate::asset::AssetVaultKey;
use crate::batch::BatchId;
use crate::block::BlockNumber;
use crate::note::{
    NoteAssets,
    NoteAttachmentArray,
    NoteExecutionHint,
    NoteTag,
    NoteType,
    Nullifier,
};
use crate::transaction::{TransactionEventId, TransactionId};
use crate::{
    ACCOUNT_UPDATE_MAX_SIZE,
    MAX_ACCOUNTS_PER_BATCH,
    MAX_INPUT_NOTES_PER_BATCH,
    MAX_INPUT_NOTES_PER_TX,
    MAX_NOTE_STORAGE_ITEMS,
    MAX_OUTPUT_NOTES_PER_TX,
};

#[cfg(any(feature = "testing", test))]
mod masm_error;
#[cfg(any(feature = "testing", test))]
pub use masm_error::MasmError;

/// The errors from the MASM code of the transaction kernel.
#[cfg(any(feature = "testing", test))]
#[rustfmt::skip]
pub mod tx_kernel;

/// The errors from the MASM code of the Miden protocol library.
#[cfg(any(feature = "testing", test))]
#[rustfmt::skip]
pub mod protocol;

// ACCOUNT COMPONENT TEMPLATE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AccountComponentTemplateError {
    #[error("storage slot name `{0}` is duplicate")]
    DuplicateSlotName(StorageSlotName),
    #[error("storage init value name `{0}` is duplicate")]
    DuplicateInitValueName(StorageValueName),
    #[error("storage value name is incorrect: {0}")]
    IncorrectStorageValueName(#[source] StorageValueNameError),
    #[error("invalid storage schema: {0}")]
    InvalidSchema(String),
    #[error("type `{0}` is not valid for `{1}` slots")]
    InvalidType(String, String),
    #[error("error deserializing component metadata: {0}")]
    MetadataDeserializationError(String),
    #[error("init storage value `{0}` was not provided")]
    InitValueNotProvided(StorageValueName),
    #[error("invalid init storage value for `{0}`: {1}")]
    InvalidInitStorageValue(StorageValueName, String),
    #[error(
        "account component storage schema cannot contain a slot with name `{0}` as it is reserved by the protocol"
    )]
    ReservedSlotName(StorageSlotName),
    #[error("error converting value into expected type: {0}")]
    StorageValueParsingError(#[source] SchemaTypeError),
    #[error("storage map contains duplicate keys")]
    StorageMapHasDuplicateKeys(#[source] Box<dyn Error + Send + Sync + 'static>),
    #[cfg(feature = "std")]
    #[error("error trying to deserialize from toml")]
    TomlDeserializationError(#[source] toml::de::Error),
    #[cfg(feature = "std")]
    #[error("error trying to deserialize from toml")]
    TomlSerializationError(#[source] toml::ser::Error),
}

// ACCOUNT ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("failed to deserialize account code")]
    AccountCodeDeserializationError(#[source] DeserializationError),
    #[error("account code does not contain an auth component")]
    AccountCodeNoAuthComponent,
    #[error("account code contains multiple auth components")]
    AccountCodeMultipleAuthComponents,
    #[error("account code must contain at least one non-auth procedure")]
    AccountCodeNoProcedures,
    #[error("account code contains {0} procedures but it may contain at most {max} procedures", max = AccountCode::MAX_NUM_PROCEDURES)]
    AccountCodeTooManyProcedures(usize),
    #[error("failed to assemble account component:\n{}", PrintDiagnostic::new(.0))]
    AccountComponentAssemblyError(Report),
    #[error("failed to merge components into one account code mast forest")]
    AccountComponentMastForestMergeError(#[source] MastForestError),
    // #[error("failed to create account component")]
    // AccountComponentTemplateInstantiationError(#[source] AccountComponentTemplateError),
    #[error("account component contains multiple authentication procedures")]
    AccountComponentMultipleAuthProcedures,
    #[error("failed to update asset vault")]
    AssetVaultUpdateError(#[source] AssetVaultError),
    #[error("account build error: {0}")]
    BuildError(String, #[source] Option<Box<AccountError>>),
    #[error("failed to parse account ID from final account header")]
    FinalAccountHeaderIdParsingFailed(#[source] AccountIdError),
    #[error("account header data has length {actual} but it must be of length {expected}")]
    HeaderDataIncorrectLength { actual: usize, expected: usize },
    #[error("active account nonce {current} plus increment {increment} overflows a felt to {new}")]
    NonceOverflow {
        current: Felt,
        increment: Felt,
        new: Felt,
    },
    #[error(
        "digest of the seed has {actual} trailing zeroes but must have at least {expected} trailing zeroes"
    )]
    SeedDigestTooFewTrailingZeros { expected: u32, actual: u32 },
    #[error("account ID {actual} computed from seed does not match ID {expected} on account")]
    AccountIdSeedMismatch { actual: AccountId, expected: AccountId },
    #[error("account ID seed was provided for an existing account")]
    ExistingAccountWithSeed,
    #[error("account ID seed was not provided for a new account")]
    NewAccountMissingSeed,
    #[error(
        "an account with a seed cannot be converted into a delta since it represents an unregistered account"
    )]
    DeltaFromAccountWithSeed,
    #[error("seed converts to an invalid account ID")]
    SeedConvertsToInvalidAccountId(#[source] AccountIdError),
    #[error("storage map root {0} not found in the account storage")]
    StorageMapRootNotFound(Word),
    #[error("storage slot {0} is not of type map")]
    StorageSlotNotMap(StorageSlotName),
    #[error("storage slot {0} is not of type value")]
    StorageSlotNotValue(StorageSlotName),
    #[error("storage slot name {0} is assigned to more than one slot")]
    DuplicateStorageSlotName(StorageSlotName),
    #[error(
        "account storage cannot contain a user-provided slot with name {} as it is reserved by the protocol",
        AccountStorage::faucet_sysdata_slot()
    )]
    StorageSlotNameMustNotBeFaucetSysdata,
    #[error("storage does not contain a slot with name {slot_name}")]
    StorageSlotNameNotFound { slot_name: StorageSlotName },
    #[error("storage does not contain a slot with ID {slot_id}")]
    StorageSlotIdNotFound { slot_id: StorageSlotId },
    #[error("storage slots must be sorted by slot ID")]
    UnsortedStorageSlots,
    #[error("number of storage slots is {0} but max possible number is {max}", max = AccountStorage::MAX_NUM_STORAGE_SLOTS)]
    StorageTooManySlots(u64),
    #[error(
        "account component at index {component_index} is incompatible with account of type {account_type}"
    )]
    UnsupportedComponentForAccountType {
        account_type: AccountType,
        component_index: usize,
    },
    #[error(
        "failed to apply full state delta to existing account; full state deltas can be converted to accounts directly"
    )]
    ApplyFullStateDeltaToAccount,
    #[error("only account deltas representing a full account can be converted to a full account")]
    PartialStateDeltaToAccount,
    #[error("maximum number of storage map leaves exceeded")]
    MaxNumStorageMapLeavesExceeded(#[source] MerkleError),
    /// This variant can be used by methods that are not inherent to the account but want to return
    /// this error type.
    #[error("{error_msg}")]
    Other {
        error_msg: Box<str>,
        // thiserror will return this when calling Error::source on AccountError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
}

impl AccountError {
    /// Creates a custom error using the [`AccountError::Other`] variant from an error message.
    pub fn other(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::Other { error_msg: message.into(), source: None }
    }

    /// Creates a custom error using the [`AccountError::Other`] variant from an error message and
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

// ACCOUNT ID ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AccountIdError {
    #[error("failed to convert bytes into account ID prefix field element")]
    AccountIdInvalidPrefixFieldElement(#[source] DeserializationError),
    #[error("failed to convert bytes into account ID suffix field element")]
    AccountIdInvalidSuffixFieldElement(#[source] DeserializationError),
    #[error("`{0}` is not a known account storage mode")]
    UnknownAccountStorageMode(Box<str>),
    #[error(r#"`{0}` is not a known account type, expected one of "FungibleFaucet", "NonFungibleFaucet", "RegularAccountImmutableCode" or "RegularAccountUpdatableCode""#)]
    UnknownAccountType(Box<str>),
    #[error("failed to parse hex string into account ID")]
    AccountIdHexParseError(#[source] HexParseError),
    #[error("`{0}` is not a known account ID version")]
    UnknownAccountIdVersion(u8),
    #[error("most significant bit of account ID suffix must be zero")]
    AccountIdSuffixMostSignificantBitMustBeZero,
    #[error("least significant byte of account ID suffix must be zero")]
    AccountIdSuffixLeastSignificantByteMustBeZero,
    #[error("failed to decode bech32 string into account ID")]
    Bech32DecodeError(#[source] Bech32Error),
}

// SLOT NAME ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum StorageSlotNameError {
    #[error("slot name must only contain characters a..z, A..Z, 0..9, double colon or underscore")]
    InvalidCharacter,
    #[error("slot names must be separated by double colons")]
    UnexpectedColon,
    #[error("slot name components must not start with an underscore")]
    UnexpectedUnderscore,
    #[error(
        "slot names must contain at least {} components separated by double colons",
        StorageSlotName::MIN_NUM_COMPONENTS
    )]
    TooShort,
    #[error("slot names must contain at most {} characters", StorageSlotName::MAX_LENGTH)]
    TooLong,
}

// ACCOUNT TREE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AccountTreeError {
    #[error(
        "account tree contains multiple account IDs that share the same prefix {duplicate_prefix}"
    )]
    DuplicateIdPrefix { duplicate_prefix: AccountIdPrefix },
    #[error(
        "entries passed to account tree contain multiple state commitments for the same account ID prefix {prefix}"
    )]
    DuplicateStateCommitments { prefix: AccountIdPrefix },
    #[error("untracked account ID {id} used in partial account tree")]
    UntrackedAccountId { id: AccountId, source: MerkleError },
    #[error("new tree root after account witness insertion does not match previous tree root")]
    TreeRootConflict(#[source] MerkleError),
    #[error("failed to apply mutations to account tree")]
    ApplyMutations(#[source] MerkleError),
    #[error("failed to compute account tree mutations")]
    ComputeMutations(#[source] MerkleError),
    #[error("smt leaf's index is not a valid account ID prefix")]
    InvalidAccountIdPrefix(#[source] AccountIdError),
    #[error("account witness merkle path depth {0} does not match AccountTree::DEPTH")]
    WitnessMerklePathDepthDoesNotMatchAccountTreeDepth(usize),
}

// ADDRESS ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("tag length {0} should be {expected} bits for network accounts",
        expected = NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH
    )]
    CustomTagLengthNotAllowedForNetworkAccounts(u8),
    #[error("tag length {0} is too large, must be less than or equal to {max}",
        max = NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH
    )]
    TagLengthTooLarge(u8),
    #[error("unknown address interface `{0}`")]
    UnknownAddressInterface(u16),
    #[error("failed to decode account ID")]
    AccountIdDecodeError(#[source] AccountIdError),
    #[error("address separator must not be included without routing parameters")]
    TrailingSeparator,
    #[error("failed to decode bech32 string into an address")]
    Bech32DecodeError(#[source] Bech32Error),
    #[error("{error_msg}")]
    DecodeError {
        error_msg: Box<str>,
        // thiserror will return this when calling Error::source on NoteError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
    #[error("found unknown routing parameter key {0}")]
    UnknownRoutingParameterKey(u8),
}

impl AddressError {
    /// Creates an [`AddressError::DecodeError`] variant from an error message.
    pub fn decode_error(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::DecodeError { error_msg: message.into(), source: None }
    }

    /// Creates an [`AddressError::DecodeError`] variant from an error message and
    /// a source error.
    pub fn decode_error_with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message: String = message.into();
        Self::DecodeError {
            error_msg: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

// BECH32 ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum Bech32Error {
    #[error(transparent)]
    DecodeError(Box<dyn Error + Send + Sync + 'static>),
    #[error("found unknown address type {0} which is not the expected {account_addr} account ID address type",
      account_addr = AddressType::AccountId as u8
    )]
    UnknownAddressType(u8),
    #[error("expected bech32 data to be of length {expected} but it was of length {actual}")]
    InvalidDataLength { expected: usize, actual: usize },
}

// NETWORK ID ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NetworkIdError {
    #[error("failed to parse string into a network ID")]
    NetworkIdParseError(#[source] Box<dyn Error + Send + Sync + 'static>),
}

// ACCOUNT DELTA ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AccountDeltaError {
    #[error("storage slot {0} was used as different slot types")]
    StorageSlotUsedAsDifferentTypes(StorageSlotName),
    #[error("non fungible vault can neither be added nor removed twice")]
    DuplicateNonFungibleVaultUpdate(NonFungibleAsset),
    #[error(
        "fungible asset issued by faucet {faucet_id} has delta {delta} which overflows when added to current value {current}"
    )]
    FungibleAssetDeltaOverflow {
        faucet_id: AccountId,
        current: i64,
        delta: i64,
    },
    #[error(
        "account update of type `{left_update_type}` cannot be merged with account update of type `{right_update_type}`"
    )]
    IncompatibleAccountUpdates {
        left_update_type: &'static str,
        right_update_type: &'static str,
    },
    #[error("account delta could not be applied to account {account_id}")]
    AccountDeltaApplicationFailed {
        account_id: AccountId,
        source: AccountError,
    },
    #[error("non-empty account storage or vault delta with zero nonce delta is not allowed")]
    NonEmptyStorageOrVaultDeltaWithZeroNonceDelta,
    #[error(
        "account nonce increment {current} plus the other nonce increment {increment} overflows a felt to {new}"
    )]
    NonceIncrementOverflow {
        current: Felt,
        increment: Felt,
        new: Felt,
    },
    #[error("account ID {0} in fungible asset delta is not of type fungible faucet")]
    NotAFungibleFaucetId(AccountId),
    #[error("cannot merge two full state deltas")]
    MergingFullStateDeltas,
}

// STORAGE MAP ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum StorageMapError {
    #[error("map entries contain key {key} twice with values {value0} and {value1}")]
    DuplicateKey { key: Word, value0: Word, value1: Word },
    #[error("map key {raw_key} is not present in provided SMT proof")]
    MissingKey { raw_key: Word },
}

// BATCH ACCOUNT UPDATE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum BatchAccountUpdateError {
    #[error(
        "account update for account {expected_account_id} cannot be merged with update from transaction {transaction} which was executed against account {actual_account_id}"
    )]
    AccountUpdateIdMismatch {
        transaction: TransactionId,
        expected_account_id: AccountId,
        actual_account_id: AccountId,
    },
    #[error(
        "final state commitment in account update from transaction {0} does not match initial state of current update"
    )]
    AccountUpdateInitialStateMismatch(TransactionId),
    #[error("failed to merge account delta from transaction {0}")]
    TransactionUpdateMergeError(TransactionId, #[source] Box<AccountDeltaError>),
}

// ASSET ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AssetError {
    #[error(
      "fungible asset amount {0} exceeds the max allowed amount of {max_amount}",
      max_amount = FungibleAsset::MAX_AMOUNT
    )]
    FungibleAssetAmountTooBig(u64),
    #[error("subtracting {subtrahend} from fungible asset amount {minuend} would underflow")]
    FungibleAssetAmountNotSufficient { minuend: u64, subtrahend: u64 },
    #[error("fungible asset word {0} does not contain expected ZERO at word index 1")]
    FungibleAssetExpectedZero(Word),
    #[error(
        "cannot add fungible asset with issuer {other_issuer} to fungible asset with issuer {original_issuer}"
    )]
    FungibleAssetInconsistentFaucetIds {
        original_issuer: AccountId,
        other_issuer: AccountId,
    },
    #[error("faucet account ID in asset is invalid")]
    InvalidFaucetAccountId(#[source] Box<dyn Error + Send + Sync + 'static>),
    #[error("faucet account ID in asset has a non-faucet prefix: {}", .0)]
    InvalidFaucetAccountIdPrefix(AccountIdPrefix),
    #[error(
      "faucet id {0} of type {id_type} must be of type {expected_ty} for fungible assets",
      id_type = .0.account_type(),
      expected_ty = AccountType::FungibleFaucet
    )]
    FungibleFaucetIdTypeMismatch(AccountId),
    #[error(
      "faucet id {0} of type {id_type} must be of type {expected_ty} for non fungible assets",
      id_type = .0.account_type(),
      expected_ty = AccountType::NonFungibleFaucet
    )]
    NonFungibleFaucetIdTypeMismatch(AccountIdPrefix),
    #[error("asset vault key {actual} does not match expected asset vault key {expected}")]
    AssetVaultKeyMismatch { actual: Word, expected: Word },
}

// TOKEN SYMBOL ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TokenSymbolError {
    #[error("token symbol value {0} cannot exceed {max}", max = TokenSymbol::MAX_ENCODED_VALUE)]
    ValueTooLarge(u64),
    #[error("token symbol should have length between 1 and 6 characters, but {0} was provided")]
    InvalidLength(usize),
    #[error("token symbol contains a character that is not uppercase ASCII")]
    InvalidCharacter,
    #[error("token symbol data left after decoding the specified number of characters")]
    DataNotFullyDecoded,
}

// ASSET VAULT ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AssetVaultError {
    #[error("adding fungible asset amounts would exceed maximum allowed amount")]
    AddFungibleAssetBalanceError(#[source] AssetError),
    #[error("provided assets contain duplicates")]
    DuplicateAsset(#[source] MerkleError),
    #[error("non fungible asset {0} already exists in the vault")]
    DuplicateNonFungibleAsset(NonFungibleAsset),
    #[error("fungible asset {0} does not exist in the vault")]
    FungibleAssetNotFound(FungibleAsset),
    #[error("faucet id {0} is not a fungible faucet id")]
    NotAFungibleFaucetId(AccountId),
    #[error("non fungible asset {0} does not exist in the vault")]
    NonFungibleAssetNotFound(NonFungibleAsset),
    #[error("subtracting fungible asset amounts would underflow")]
    SubtractFungibleAssetBalanceError(#[source] AssetError),
    #[error("maximum number of asset vault leaves exceeded")]
    MaxLeafEntriesExceeded(#[source] MerkleError),
}

// PARTIAL ASSET VAULT ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum PartialAssetVaultError {
    #[error("provided SMT entry {entry} is not a valid asset")]
    InvalidAssetInSmt { entry: Word, source: AssetError },
    #[error("expected asset vault key to be {expected} but it was {actual}")]
    AssetVaultKeyMismatch { expected: AssetVaultKey, actual: Word },
    #[error("failed to add asset proof")]
    FailedToAddProof(#[source] MerkleError),
    #[error("asset is not tracked in the partial vault")]
    UntrackedAsset(#[source] MerkleError),
}

// NOTE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("note tag length {0} exceeds the maximum of {max}", max = NoteTag::MAX_ACCOUNT_TARGET_TAG_LENGTH)]
    NoteTagLengthTooLarge(u8),
    #[error("duplicate fungible asset from issuer {0} in note")]
    DuplicateFungibleAsset(AccountId),
    #[error("duplicate non fungible asset {0} in note")]
    DuplicateNonFungibleAsset(NonFungibleAsset),
    #[error("note type {0} is inconsistent with note tag {1}")]
    InconsistentNoteTag(NoteType, u64),
    #[error("adding fungible asset amounts would exceed maximum allowed amount")]
    AddFungibleAssetBalanceError(#[source] AssetError),
    #[error("note sender is not a valid account ID")]
    NoteSenderInvalidAccountId(#[source] AccountIdError),
    #[error(
        "note execution hint tag {0} must be in range {from}..={to}",
        from = NoteExecutionHint::NONE_TAG,
        to = NoteExecutionHint::ON_BLOCK_SLOT_TAG,
    )]
    NoteExecutionHintTagOutOfRange(u8),
    #[error("note execution hint after block variant cannot contain u32::MAX")]
    NoteExecutionHintAfterBlockCannotBeU32Max,
    #[error("invalid note execution hint payload {1} for tag {0}")]
    InvalidNoteExecutionHintPayload(u8, u32),
    #[error(
    "note type {0} does not match any of the valid note types {public} or {private}",
    public = NoteType::Public,
    private = NoteType::Private,
    )]
    UnknownNoteType(Box<str>),
    #[error("note location index {node_index_in_block} is out of bounds 0..={highest_index}")]
    NoteLocationIndexOutOfBounds {
        node_index_in_block: u16,
        highest_index: usize,
    },
    #[error("note network execution requires a public note but note is of type {0}")]
    NetworkExecutionRequiresPublicNote(NoteType),
    #[error("failed to assemble note script:\n{}", PrintDiagnostic::new(.0))]
    NoteScriptAssemblyError(Report),
    #[error("failed to deserialize note script")]
    NoteScriptDeserializationError(#[source] DeserializationError),
    #[error("note contains {0} assets which exceeds the maximum of {max}", max = NoteAssets::MAX_NUM_ASSETS)]
    TooManyAssets(usize),
    #[error("note contains {0} storage items which exceeds the maximum of {max}", max = MAX_NOTE_STORAGE_ITEMS)]
    TooManyStorageItems(usize),
    #[error("note tag requires a public note but the note is of type {0}")]
    PublicNoteRequired(NoteType),
    #[error(
        "note attachment cannot commit to more than {} elements",
        NoteAttachmentArray::MAX_NUM_ELEMENTS
    )]
    NoteAttachmentArraySizeExceeded(usize),
    #[error("unknown note attachment kind {0}")]
    UnknownNoteAttachmentKind(u8),
    #[error("note attachment of kind None must have attachment scheme None")]
    AttachmentKindNoneMustHaveAttachmentSchemeNone,
    #[error("{error_msg}")]
    Other {
        error_msg: Box<str>,
        // thiserror will return this when calling Error::source on NoteError.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
}

impl NoteError {
    /// Creates a custom error using the [`NoteError::Other`] variant from an error message.
    pub fn other(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self::Other { error_msg: message.into(), source: None }
    }

    /// Creates a custom error using the [`NoteError::Other`] variant from an error message and
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

// PARTIAL BLOCKCHAIN ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum PartialBlockchainError {
    #[error(
        "block num {block_num} exceeds chain length {chain_length} implied by the partial blockchain"
    )]
    BlockNumTooBig {
        chain_length: usize,
        block_num: BlockNumber,
    },

    #[error("duplicate block {block_num} in partial blockchain")]
    DuplicateBlock { block_num: BlockNumber },

    #[error("partial blockchain does not track authentication paths for block {block_num}")]
    UntrackedBlock { block_num: BlockNumber },

    #[error(
        "provided block header with number {block_num} and commitment {block_commitment} is not tracked by partial MMR"
    )]
    BlockHeaderCommitmentMismatch {
        block_num: BlockNumber,
        block_commitment: Word,
        source: MmrError,
    },
}

impl PartialBlockchainError {
    pub fn block_num_too_big(chain_length: usize, block_num: BlockNumber) -> Self {
        Self::BlockNumTooBig { chain_length, block_num }
    }

    pub fn duplicate_block(block_num: BlockNumber) -> Self {
        Self::DuplicateBlock { block_num }
    }

    pub fn untracked_block(block_num: BlockNumber) -> Self {
        Self::UntrackedBlock { block_num }
    }
}

// TRANSACTION SCRIPT ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionScriptError {
    #[error("failed to assemble transaction script:\n{}", PrintDiagnostic::new(.0))]
    AssemblyError(Report),
}

// TRANSACTION INPUT ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionInputError {
    #[error("transaction input note with nullifier {0} is a duplicate")]
    DuplicateInputNote(Nullifier),
    #[error("partial blockchain has length {actual} which does not match block number {expected}")]
    InconsistentChainLength {
        expected: BlockNumber,
        actual: BlockNumber,
    },
    #[error(
        "partial blockchain has commitment {actual} which does not match the block header's chain commitment {expected}"
    )]
    InconsistentChainCommitment { expected: Word, actual: Word },
    #[error("block in which input note with id {0} was created is not in partial blockchain")]
    InputNoteBlockNotInPartialBlockchain(NoteId),
    #[error("input note with id {0} was not created in block {1}")]
    InputNoteNotInBlock(NoteId, BlockNumber),
    #[error(
        "total number of input notes is {0} which exceeds the maximum of {MAX_INPUT_NOTES_PER_TX}"
    )]
    TooManyInputNotes(usize),
}

// TRANSACTION INPUTS EXTRACTION ERROR
// ===============================================================================================

#[derive(Debug, Error)]
pub enum TransactionInputsExtractionError {
    #[error("specified foreign account id matches the transaction input's account id")]
    AccountNotForeign,
    #[error("foreign account data not found in advice map for account {0}")]
    ForeignAccountNotFound(AccountId),
    #[error("foreign account code not found for account {0}")]
    ForeignAccountCodeNotFound(AccountId),
    #[error("storage header data not found in advice map for account {0}")]
    StorageHeaderNotFound(AccountId),
    #[error("failed to handle account data")]
    AccountError(#[from] AccountError),
    #[error("failed to handle merkle data")]
    MerkleError(#[from] MerkleError),
    #[error("failed to handle account tree data")]
    AccountTreeError(#[from] AccountTreeError),
    #[error("missing vault root from Merkle store")]
    MissingVaultRoot,
    #[error("missing storage map root from Merkle store")]
    MissingMapRoot,
    #[error("failed to construct SMT proof")]
    SmtProofError(#[from] SmtProofError),
    #[error("failed to construct an asset")]
    AssetError(#[from] AssetError),
    #[error("failed to handle storage map data")]
    StorageMapError(#[from] StorageMapError),
    #[error("failed to convert elements to leaf index: {0}")]
    LeafConversionError(String),
    #[error("failed to construct SMT leaf")]
    SmtLeafError(#[from] SmtLeafError),
}

// TRANSACTION OUTPUT ERROR
// ===============================================================================================

#[derive(Debug, Error)]
pub enum TransactionOutputError {
    #[error("transaction output note with id {0} is a duplicate")]
    DuplicateOutputNote(NoteId),
    #[error("final account commitment is not in the advice map")]
    FinalAccountCommitmentMissingInAdviceMap,
    #[error("fee asset is not a fungible asset")]
    FeeAssetNotFungibleAsset(#[source] AssetError),
    #[error("failed to parse final account header")]
    FinalAccountHeaderParseFailure(#[source] AccountError),
    #[error(
        "output notes commitment {expected} from kernel does not match computed commitment {actual}"
    )]
    OutputNotesCommitmentInconsistent { expected: Word, actual: Word },
    #[error("transaction kernel output stack is invalid: {0}")]
    OutputStackInvalid(String),
    #[error(
        "total number of output notes is {0} which exceeds the maximum of {MAX_OUTPUT_NOTES_PER_TX}"
    )]
    TooManyOutputNotes(usize),
    #[error("failed to process account update commitment: {0}")]
    AccountUpdateCommitment(Box<str>),
}

// TRANSACTION EVENT PARSING ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionEventError {
    #[error("event id {0} is not a valid transaction event")]
    InvalidTransactionEvent(EventId, Option<&'static str>),
    #[error("event id {0} is not a transaction kernel event")]
    NotTransactionEvent(EventId, Option<&'static str>),
    #[error("event id {0} can only be emitted from the root context")]
    NotRootContext(TransactionEventId),
}

// TRANSACTION TRACE PARSING ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum TransactionTraceParsingError {
    #[error("trace id {0} is an unknown transaction kernel trace")]
    UnknownTransactionTrace(u32),
}

// PROVEN TRANSACTION ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum ProvenTransactionError {
    #[error(
        "proven transaction's final account commitment {tx_final_commitment} and account details commitment {details_commitment} must match"
    )]
    AccountFinalCommitmentMismatch {
        tx_final_commitment: Word,
        details_commitment: Word,
    },
    #[error(
        "proven transaction's final account ID {tx_account_id} and account details id {details_account_id} must match"
    )]
    AccountIdMismatch {
        tx_account_id: AccountId,
        details_account_id: AccountId,
    },
    #[error("failed to construct input notes for proven transaction")]
    InputNotesError(TransactionInputError),
    #[error("private account {0} should not have account details")]
    PrivateAccountWithDetails(AccountId),
    #[error("account {0} with public state is missing its account details")]
    PublicStateAccountMissingDetails(AccountId),
    #[error("new account {id} with public state must be accompanied by a full state delta")]
    NewPublicStateAccountRequiresFullStateDelta { id: AccountId, source: AccountError },
    #[error(
        "existing account {0} with public state should only provide delta updates instead of full details"
    )]
    ExistingPublicStateAccountRequiresDeltaDetails(AccountId),
    #[error("failed to construct output notes for proven transaction")]
    OutputNotesError(TransactionOutputError),
    #[error(
        "account update of size {update_size} for account {account_id} exceeds maximum update size of {ACCOUNT_UPDATE_MAX_SIZE}"
    )]
    AccountUpdateSizeLimitExceeded {
        account_id: AccountId,
        update_size: usize,
    },
    #[error("proven transaction neither changed the account state, nor consumed any notes")]
    EmptyTransaction,
    #[error("failed to validate account delta in transaction account update")]
    AccountDeltaCommitmentMismatch(#[source] Box<dyn Error + Send + Sync + 'static>),
}

// PROPOSED BATCH ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum ProposedBatchError {
    #[error(
        "transaction batch has {0} input notes but at most {MAX_INPUT_NOTES_PER_BATCH} are allowed"
    )]
    TooManyInputNotes(usize),

    #[error(
        "transaction batch has {0} output notes but at most {MAX_OUTPUT_NOTES_PER_BATCH} are allowed"
    )]
    TooManyOutputNotes(usize),

    #[error(
        "transaction batch has {0} account updates but at most {MAX_ACCOUNTS_PER_BATCH} are allowed"
    )]
    TooManyAccountUpdates(usize),

    #[error(
        "transaction {transaction_id} expires at block number {transaction_expiration_num} which is not greater than the number of the batch's reference block {reference_block_num}"
    )]
    ExpiredTransaction {
        transaction_id: TransactionId,
        transaction_expiration_num: BlockNumber,
        reference_block_num: BlockNumber,
    },

    #[error("transaction batch must contain at least one transaction")]
    EmptyTransactionBatch,

    #[error("transaction {transaction_id} appears twice in the proposed batch input")]
    DuplicateTransaction { transaction_id: TransactionId },

    #[error(
        "transaction {second_transaction_id} consumes the note with nullifier {note_nullifier} that is also consumed by another transaction {first_transaction_id} in the batch"
    )]
    DuplicateInputNote {
        note_nullifier: Nullifier,
        first_transaction_id: TransactionId,
        second_transaction_id: TransactionId,
    },

    #[error(
        "transaction {second_transaction_id} creates the note with id {note_id} that is also created by another transaction {first_transaction_id} in the batch"
    )]
    DuplicateOutputNote {
        note_id: NoteId,
        first_transaction_id: TransactionId,
        second_transaction_id: TransactionId,
    },

    #[error(
        "note commitment mismatch for note {id}: (input: {input_commitment}, output: {output_commitment})"
    )]
    NoteCommitmentMismatch {
        id: NoteId,
        input_commitment: Word,
        output_commitment: Word,
    },

    #[error("failed to merge transaction delta into account {account_id}")]
    AccountUpdateError {
        account_id: AccountId,
        source: BatchAccountUpdateError,
    },

    #[error(
        "unable to prove unauthenticated note inclusion because block {block_number} in which note with id {note_id} was created is not in partial blockchain"
    )]
    UnauthenticatedInputNoteBlockNotInPartialBlockchain {
        block_number: BlockNumber,
        note_id: NoteId,
    },

    #[error(
        "unable to prove unauthenticated note inclusion of note {note_id} in block {block_num}"
    )]
    UnauthenticatedNoteAuthenticationFailed {
        note_id: NoteId,
        block_num: BlockNumber,
        source: MerkleError,
    },

    #[error("partial blockchain has length {actual} which does not match block number {expected}")]
    InconsistentChainLength {
        expected: BlockNumber,
        actual: BlockNumber,
    },

    #[error(
        "partial blockchain has root {actual} which does not match block header's root {expected}"
    )]
    InconsistentChainRoot { expected: Word, actual: Word },

    #[error(
        "block {block_reference} referenced by transaction {transaction_id} is not in the partial blockchain"
    )]
    MissingTransactionBlockReference {
        block_reference: Word,
        transaction_id: TransactionId,
    },
}

// PROVEN BATCH ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum ProvenBatchError {
    #[error("failed to verify transaction {transaction_id} in transaction batch")]
    TransactionVerificationFailed {
        transaction_id: TransactionId,
        source: Box<dyn Error + Send + Sync + 'static>,
    },
    #[error(
        "batch expiration block number {batch_expiration_block_num} is not greater than the reference block number {reference_block_num}"
    )]
    InvalidBatchExpirationBlockNum {
        batch_expiration_block_num: BlockNumber,
        reference_block_num: BlockNumber,
    },
}

// PROPOSED BLOCK ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum ProposedBlockError {
    #[error("block must contain at least one transaction batch")]
    EmptyBlock,

    #[error("block must contain at most {MAX_BATCHES_PER_BLOCK} transaction batches")]
    TooManyBatches,

    #[error(
        "batch {batch_id} expired at block {batch_expiration_block_num} but the current block number is {current_block_num}"
    )]
    ExpiredBatch {
        batch_id: BatchId,
        batch_expiration_block_num: BlockNumber,
        current_block_num: BlockNumber,
    },

    #[error("batch {batch_id} appears twice in the block inputs")]
    DuplicateBatch { batch_id: BatchId },

    #[error(
        "batch {second_batch_id} consumes the note with nullifier {note_nullifier} that is also consumed by another batch {first_batch_id} in the block"
    )]
    DuplicateInputNote {
        note_nullifier: Nullifier,
        first_batch_id: BatchId,
        second_batch_id: BatchId,
    },

    #[error(
        "batch {second_batch_id} creates the note with ID {note_id} that is also created by another batch {first_batch_id} in the block"
    )]
    DuplicateOutputNote {
        note_id: NoteId,
        first_batch_id: BatchId,
        second_batch_id: BatchId,
    },

    #[error(
        "timestamp {provided_timestamp} does not increase monotonically compared to timestamp {previous_timestamp} from the previous block header"
    )]
    TimestampDoesNotIncreaseMonotonically {
        provided_timestamp: u32,
        previous_timestamp: u32,
    },

    #[error(
        "account {account_id} is updated from the same initial state commitment {initial_state_commitment} by multiple conflicting batches with IDs {first_batch_id} and {second_batch_id}"
    )]
    ConflictingBatchesUpdateSameAccount {
        account_id: AccountId,
        initial_state_commitment: Word,
        first_batch_id: BatchId,
        second_batch_id: BatchId,
    },

    #[error(
        "partial blockchain has length {chain_length} which does not match the block number {prev_block_num} of the previous block referenced by the to-be-built block"
    )]
    ChainLengthNotEqualToPreviousBlockNumber {
        chain_length: BlockNumber,
        prev_block_num: BlockNumber,
    },

    #[error(
        "partial blockchain has commitment {chain_commitment} which does not match the chain commitment {prev_block_chain_commitment} of the previous block {prev_block_num}"
    )]
    ChainRootNotEqualToPreviousBlockChainCommitment {
        chain_commitment: Word,
        prev_block_chain_commitment: Word,
        prev_block_num: BlockNumber,
    },

    #[error(
        "partial blockchain is missing block {reference_block_num} referenced by batch {batch_id} in the block"
    )]
    BatchReferenceBlockMissingFromChain {
        reference_block_num: BlockNumber,
        batch_id: BatchId,
    },

    #[error(
        "note commitment mismatch for note {id}: (input: {input_commitment}, output: {output_commitment})"
    )]
    NoteCommitmentMismatch {
        id: NoteId,
        input_commitment: Word,
        output_commitment: Word,
    },

    #[error(
        "failed to prove unauthenticated note inclusion because block {block_number} in which note with id {note_id} was created is not in partial blockchain"
    )]
    UnauthenticatedInputNoteBlockNotInPartialBlockchain {
        block_number: BlockNumber,
        note_id: NoteId,
    },

    #[error(
        "failed to prove unauthenticated note inclusion of note {note_id} in block {block_num}"
    )]
    UnauthenticatedNoteAuthenticationFailed {
        note_id: NoteId,
        block_num: BlockNumber,
        source: MerkleError,
    },

    #[error(
        "unauthenticated note with nullifier {nullifier} was not created in the same block and no inclusion proof to authenticate it was provided"
    )]
    UnauthenticatedNoteConsumed { nullifier: Nullifier },

    #[error("block inputs do not contain a proof of inclusion for account {0}")]
    MissingAccountWitness(AccountId),

    #[error(
        "account {account_id} with state {state_commitment} cannot transition to any of the remaining states {}",
        remaining_state_commitments.iter().map(Word::to_hex).collect::<Vec<_>>().join(", ")
    )]
    InconsistentAccountStateTransition {
        account_id: AccountId,
        state_commitment: Word,
        remaining_state_commitments: Vec<Word>,
    },

    #[error("no proof for nullifier {0} was provided")]
    NullifierProofMissing(Nullifier),

    #[error("note with nullifier {0} is already spent")]
    NullifierSpent(Nullifier),

    #[error("failed to merge transaction delta into account {account_id}")]
    AccountUpdateError {
        account_id: AccountId,
        source: Box<AccountDeltaError>,
    },

    #[error("failed to track account witness")]
    AccountWitnessTracking { source: AccountTreeError },

    #[error(
        "account tree root of the previous block header is {prev_block_account_root} but the root of the partial tree computed from account witnesses is {stale_account_root}, indicating that the witnesses are stale"
    )]
    StaleAccountTreeRoot {
        prev_block_account_root: Word,
        stale_account_root: Word,
    },

    #[error("account ID prefix already exists in the tree")]
    AccountIdPrefixDuplicate { source: AccountTreeError },

    #[error(
        "nullifier tree root of the previous block header is {prev_block_nullifier_root} but the root of the partial tree computed from nullifier witnesses is {stale_nullifier_root}, indicating that the witnesses are stale"
    )]
    StaleNullifierTreeRoot {
        prev_block_nullifier_root: Word,
        stale_nullifier_root: Word,
    },

    #[error("nullifier witness has a different root than the current nullifier tree root")]
    NullifierWitnessRootMismatch(NullifierTreeError),
}

// FEE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum FeeError {
    #[error("native asset of the chain must be a fungible faucet but was of type {account_type}")]
    NativeAssetIdNotFungible { account_type: AccountType },
}

// NULLIFIER TREE ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum NullifierTreeError {
    #[error(
        "entries passed to nullifier tree contain multiple block numbers for the same nullifier"
    )]
    DuplicateNullifierBlockNumbers(#[source] MerkleError),

    #[error("attempt to mark nullifier {0} as spent but it is already spent")]
    NullifierAlreadySpent(Nullifier),

    #[error("maximum number of nullifier tree leaves exceeded")]
    MaxLeafEntriesExceeded(#[source] MerkleError),

    #[error("nullifier {nullifier} is not tracked by the partial nullifier tree")]
    UntrackedNullifier {
        nullifier: Nullifier,
        source: MerkleError,
    },

    #[error("new tree root after nullifier witness insertion does not match previous tree root")]
    TreeRootConflict(#[source] MerkleError),

    #[error("failed to compute nullifier tree mutations")]
    ComputeMutations(#[source] MerkleError),

    #[error("invalid nullifier block number")]
    InvalidNullifierBlockNumber(Word),
}

// AUTH SCHEME ERROR
// ================================================================================================

#[derive(Debug, Error)]
pub enum AuthSchemeError {
    #[error("auth scheme identifier `{0}` is not valid")]
    InvalidAuthSchemeIdentifier(u8),
}
