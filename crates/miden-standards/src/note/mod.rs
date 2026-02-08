use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::error::Error;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteScript};
use miden_protocol::{Felt, Word};

use crate::account::faucets::{BasicFungibleFaucet, NetworkFungibleFaucet};
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::wallets::BasicWallet;

mod burn;
pub use burn::BurnNote;

mod execution_hint;
pub use execution_hint::NoteExecutionHint;

mod mint;
pub use mint::{MintNote, MintNoteStorage};

mod p2id;
pub use p2id::P2idNote;

mod p2ide;
pub use p2ide::P2ideNote;

mod swap;
pub use swap::SwapNote;

mod network_account_target;
pub use network_account_target::{NetworkAccountTarget, NetworkAccountTargetError};

mod standard_note_attachment;
pub use standard_note_attachment::StandardNoteAttachment;

// STANDARD NOTE
// ================================================================================================

/// The enum holding the types of standard notes provided by `miden-standards`.
pub enum StandardNote {
    P2ID,
    P2IDE,
    SWAP,
    MINT,
    BURN,
}

impl StandardNote {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a [StandardNote] instance based on the note script of the provided [Note]. Returns
    /// `None` if the provided note is not a standard note.
    pub fn from_note(note: &Note) -> Option<Self> {
        let note_script_root = note.script().root();

        if note_script_root == P2idNote::script_root() {
            return Some(Self::P2ID);
        }
        if note_script_root == P2ideNote::script_root() {
            return Some(Self::P2IDE);
        }
        if note_script_root == SwapNote::script_root() {
            return Some(Self::SWAP);
        }
        if note_script_root == MintNote::script_root() {
            return Some(Self::MINT);
        }
        if note_script_root == BurnNote::script_root() {
            return Some(Self::BURN);
        }

        None
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the expected number of storage items of the active note.
    pub fn expected_num_storage_items(&self) -> usize {
        match self {
            Self::P2ID => P2idNote::NUM_STORAGE_ITEMS,
            Self::P2IDE => P2ideNote::NUM_STORAGE_ITEMS,
            Self::SWAP => SwapNote::NUM_STORAGE_ITEMS,
            Self::MINT => MintNote::NUM_STORAGE_ITEMS_PRIVATE,
            Self::BURN => BurnNote::NUM_STORAGE_ITEMS,
        }
    }

    /// Returns the note script of the current [StandardNote] instance.
    pub fn script(&self) -> NoteScript {
        match self {
            Self::P2ID => P2idNote::script(),
            Self::P2IDE => P2ideNote::script(),
            Self::SWAP => SwapNote::script(),
            Self::MINT => MintNote::script(),
            Self::BURN => BurnNote::script(),
        }
    }

    /// Returns the script root of the current [StandardNote] instance.
    pub fn script_root(&self) -> Word {
        match self {
            Self::P2ID => P2idNote::script_root(),
            Self::P2IDE => P2ideNote::script_root(),
            Self::SWAP => SwapNote::script_root(),
            Self::MINT => MintNote::script_root(),
            Self::BURN => BurnNote::script_root(),
        }
    }

    /// Returns a boolean value indicating whether this [StandardNote] is compatible with the
    /// provided [AccountInterface].
    pub fn is_compatible_with(&self, account_interface: &AccountInterface) -> bool {
        if account_interface.components().contains(&AccountComponentInterface::BasicWallet) {
            return true;
        }

        let interface_proc_digests = account_interface.get_procedure_digests();
        match self {
            Self::P2ID | &Self::P2IDE => {
                // To consume P2ID and P2IDE notes, the `receive_asset` procedure must be present in
                // the provided account interface.
                interface_proc_digests.contains(&BasicWallet::receive_asset_digest())
            },
            Self::SWAP => {
                // To consume SWAP note, the `receive_asset` and `move_asset_to_note` procedures
                // must be present in the provided account interface.
                interface_proc_digests.contains(&BasicWallet::receive_asset_digest())
                    && interface_proc_digests.contains(&BasicWallet::move_asset_to_note_digest())
            },
            Self::MINT => {
                // MINT notes work only with network fungible faucets. The network faucet uses
                // note-based authentication (checking if the note sender equals the faucet owner)
                // to authorize minting, while basic faucets have different mint procedures that
                // are not compatible with MINT notes.
                interface_proc_digests.contains(&NetworkFungibleFaucet::distribute_digest())
            },
            Self::BURN => {
                // BURN notes work with both basic and network fungible faucets because both
                // faucet types export the same `burn` procedure with identical MAST roots.
                // This allows a single BURN note script to work with either faucet type.
                interface_proc_digests.contains(&BasicFungibleFaucet::burn_digest())
                    || interface_proc_digests.contains(&NetworkFungibleFaucet::burn_digest())
            },
        }
    }

    /// Performs the inputs check of the provided standard note against the target account and the
    /// block number.
    ///
    /// This function returns:
    /// - `Some` if we can definitively determine whether the note can be consumed not by the target
    ///   account.
    /// - `None` if the consumption status of the note cannot be determined conclusively and further
    ///   checks are necessary.
    pub fn is_consumable(
        &self,
        note: &Note,
        target_account_id: AccountId,
        block_ref: BlockNumber,
    ) -> Option<NoteConsumptionStatus> {
        match self.is_consumable_inner(note, target_account_id, block_ref) {
            Ok(status) => status,
            Err(err) => {
                let err: Box<dyn Error + Send + Sync + 'static> = Box::from(err);
                Some(NoteConsumptionStatus::NeverConsumable(err))
            },
        }
    }

    /// Performs the inputs check of the provided note against the target account and the block
    /// number.
    ///
    /// It performs:
    /// - for `P2ID` note:
    ///     - check that note storage has correct number of values.
    ///     - assertion that the account ID provided by the note storage is equal to the target
    ///       account ID.
    /// - for `P2IDE` note:
    ///     - check that note storage has correct number of values.
    ///     - check that the target account is either the receiver account or the sender account.
    ///     - check that depending on whether the target account is sender or receiver, it could be
    ///       either consumed, or consumed after timelock height, or consumed after reclaim height.
    fn is_consumable_inner(
        &self,
        note: &Note,
        target_account_id: AccountId,
        block_ref: BlockNumber,
    ) -> Result<Option<NoteConsumptionStatus>, StaticAnalysisError> {
        match self {
            StandardNote::P2ID => {
                let input_account_id = parse_p2id_storage(note.storage().items())?;

                if input_account_id == target_account_id {
                    Ok(Some(NoteConsumptionStatus::ConsumableWithAuthorization))
                } else {
                    Ok(Some(NoteConsumptionStatus::NeverConsumable("account ID provided to the P2ID note storage doesn't match the target account ID".into())))
                }
            },
            StandardNote::P2IDE => {
                let (receiver_account_id, reclaim_height, timelock_height) =
                    parse_p2ide_storage(note.storage().items())?;

                let current_block_height = block_ref.as_u32();

                // block height after which sender account can consume the note
                let consumable_after = reclaim_height.max(timelock_height);

                // handle the case when the target account of the transaction is sender
                if target_account_id == note.metadata().sender() {
                    // For the sender, the current block height needs to have reached both reclaim
                    // and timelock height to be consumable.
                    if current_block_height >= consumable_after {
                        Ok(Some(NoteConsumptionStatus::ConsumableWithAuthorization))
                    } else {
                        Ok(Some(NoteConsumptionStatus::ConsumableAfter(BlockNumber::from(
                            consumable_after,
                        ))))
                    }
                // handle the case when the target account of the transaction is receiver
                } else if target_account_id == receiver_account_id {
                    // For the receiver, the current block height needs to have reached only the
                    // timelock height to be consumable: we can ignore the reclaim height in this
                    // case
                    if current_block_height >= timelock_height {
                        Ok(Some(NoteConsumptionStatus::ConsumableWithAuthorization))
                    } else {
                        Ok(Some(NoteConsumptionStatus::ConsumableAfter(BlockNumber::from(
                            timelock_height,
                        ))))
                    }
                // if the target account is neither the sender nor the receiver (from the note's
                // storage), then this account cannot consume the note
                } else {
                    Ok(Some(NoteConsumptionStatus::NeverConsumable(
                        "target account of the transaction does not match neither the receiver account specified by the P2IDE storage, nor the sender account".into()
                    )))
                }
            },

            // the consumption status of any other note cannot be determined by the static analysis,
            // further checks are necessary.
            _ => Ok(None),
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the receiver account ID parsed from the provided P2ID note storage.
///
/// # Errors
///
/// Returns an error if:
/// - the length of the provided note storage array is not equal to the expected number of storage
///   items of the P2ID note.
/// - first two elements of the note storage array does not form the valid account ID.
fn parse_p2id_storage(note_storage: &[Felt]) -> Result<AccountId, StaticAnalysisError> {
    if note_storage.len() != StandardNote::P2ID.expected_num_storage_items() {
        return Err(StaticAnalysisError::new(format!(
            "P2ID note should have {} storage items, but {} was provided",
            StandardNote::P2ID.expected_num_storage_items(),
            note_storage.len()
        )));
    }

    try_read_account_id_from_storage(note_storage)
}

/// Returns the receiver account ID, reclaim height and timelock height parsed from the provided
/// P2IDE note storage.
///
/// # Errors
///
/// Returns an error if:
/// - the length of the provided note storage array is not equal to the expected number of storage
///   items of the P2IDE note.
/// - first two elements of the note storage array does not form the valid account ID.
/// - third note storage array element (reclaim height) is not a valid u32 value.
/// - fourth note storage array element (timelock height) is not a valid u32 value.
fn parse_p2ide_storage(
    note_storage: &[Felt],
) -> Result<(AccountId, u32, u32), StaticAnalysisError> {
    if note_storage.len() != StandardNote::P2IDE.expected_num_storage_items() {
        return Err(StaticAnalysisError::new(format!(
            "P2IDE note should have {} storage items, but {} was provided",
            StandardNote::P2IDE.expected_num_storage_items(),
            note_storage.len()
        )));
    }

    let receiver_account_id = try_read_account_id_from_storage(note_storage)?;

    let reclaim_height = u32::try_from(note_storage[2])
        .map_err(|_err| StaticAnalysisError::new("reclaim block height should be a u32"))?;

    let timelock_height = u32::try_from(note_storage[3])
        .map_err(|_err| StaticAnalysisError::new("timelock block height should be a u32"))?;

    Ok((receiver_account_id, reclaim_height, timelock_height))
}

/// Reads the account ID from the first two note storage values.
///
/// Returns None if the note storage values used to construct the account ID are invalid.
fn try_read_account_id_from_storage(
    note_storage: &[Felt],
) -> Result<AccountId, StaticAnalysisError> {
    if note_storage.len() < 2 {
        return Err(StaticAnalysisError::new(format!(
            "P2ID and P2IDE notes should have at least 2 note storage items, but {} was provided",
            note_storage.len()
        )));
    }

    AccountId::try_from([note_storage[1], note_storage[0]]).map_err(|source| {
        StaticAnalysisError::with_source(
            "failed to create an account ID from the first two note storage items",
            source,
        )
    })
}

// HELPER STRUCTURES
// ================================================================================================

/// Describes if a note could be consumed under a specific conditions: target account state
/// and block height.
///
/// The status does not account for any authorization that may be required to consume the
/// note, nor does it indicate whether the account has sufficient fees to consume it.
#[derive(Debug)]
pub enum NoteConsumptionStatus {
    /// The note can be consumed by the account at the specified block height.
    Consumable,
    /// The note can be consumed by the account after the required block height is achieved.
    ConsumableAfter(BlockNumber),
    /// The note can be consumed by the account if proper authorization is provided.
    ConsumableWithAuthorization,
    /// The note cannot be consumed by the account at the specified conditions (i.e., block
    /// height and account state).
    UnconsumableConditions,
    /// The note cannot be consumed by the specified account under any conditions.
    NeverConsumable(Box<dyn Error + Send + Sync + 'static>),
}

impl Clone for NoteConsumptionStatus {
    fn clone(&self) -> Self {
        match self {
            NoteConsumptionStatus::Consumable => NoteConsumptionStatus::Consumable,
            NoteConsumptionStatus::ConsumableAfter(block_height) => {
                NoteConsumptionStatus::ConsumableAfter(*block_height)
            },
            NoteConsumptionStatus::ConsumableWithAuthorization => {
                NoteConsumptionStatus::ConsumableWithAuthorization
            },
            NoteConsumptionStatus::UnconsumableConditions => {
                NoteConsumptionStatus::UnconsumableConditions
            },
            NoteConsumptionStatus::NeverConsumable(error) => {
                let err = error.to_string();
                NoteConsumptionStatus::NeverConsumable(err.into())
            },
        }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("{message}")]
struct StaticAnalysisError {
    /// Stack size of `Box<str>` is smaller than String.
    message: Box<str>,
    /// thiserror will return this when calling Error::source on StaticAnalysisError.
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl StaticAnalysisError {
    /// Creates a new static analysis error from an error message.
    pub fn new(message: impl Into<String>) -> Self {
        let message: String = message.into();
        Self { message: message.into(), source: None }
    }

    /// Creates a new static analysis error from an error message and a source error.
    pub fn with_source(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        let message: String = message.into();
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}
