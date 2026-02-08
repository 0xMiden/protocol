use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::error::Error;

use miden_core::field::PrimeField64;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteScript};
use miden_protocol::utils::Deserializable;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::Program;
use miden_protocol::{Felt, Word};

use crate::account::faucets::{BasicFungibleFaucet, NetworkFungibleFaucet};
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::wallets::BasicWallet;

// WELL KNOWN NOTE SCRIPTS
// ================================================================================================

// Initialize the P2ID note script only once
static P2ID_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/P2ID.masb"));
    let program = Program::read_from_bytes(bytes).expect("Shipped P2ID script is well-formed");
    NoteScript::new(program)
});

// Initialize the P2IDE note script only once
static P2IDE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/P2IDE.masb"));
    let program = Program::read_from_bytes(bytes).expect("Shipped P2IDE script is well-formed");
    NoteScript::new(program)
});

// Initialize the SWAP note script only once
static SWAP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/SWAP.masb"));
    let program = Program::read_from_bytes(bytes).expect("Shipped SWAP script is well-formed");
    NoteScript::new(program)
});

// Initialize the MINT note script only once
static MINT_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/MINT.masb"));
    let program = Program::read_from_bytes(bytes).expect("Shipped MINT script is well-formed");
    NoteScript::new(program)
});

// Initialize the BURN note script only once
static BURN_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/assets/note_scripts/BURN.masb"));
    let program = Program::read_from_bytes(bytes).expect("Shipped BURN script is well-formed");
    NoteScript::new(program)
});

/// Returns the P2ID (Pay-to-ID) note script.
fn p2id() -> NoteScript {
    P2ID_SCRIPT.clone()
}

/// Returns the P2ID (Pay-to-ID) note script root.
fn p2id_root() -> Word {
    P2ID_SCRIPT.root()
}

/// Returns the P2IDE (Pay-to-ID with optional reclaim & timelock) note script.
fn p2ide() -> NoteScript {
    P2IDE_SCRIPT.clone()
}

/// Returns the P2IDE (Pay-to-ID with optional reclaim & timelock) note script root.
fn p2ide_root() -> Word {
    P2IDE_SCRIPT.root()
}

/// Returns the SWAP (Swap note) note script.
fn swap() -> NoteScript {
    SWAP_SCRIPT.clone()
}

/// Returns the SWAP (Swap note) note script root.
fn swap_root() -> Word {
    SWAP_SCRIPT.root()
}

/// Returns the MINT (Mint note) note script.
fn mint() -> NoteScript {
    MINT_SCRIPT.clone()
}

/// Returns the MINT (Mint note) note script root.
fn mint_root() -> Word {
    MINT_SCRIPT.root()
}

/// Returns the BURN (Burn note) note script.
fn burn() -> NoteScript {
    BURN_SCRIPT.clone()
}

/// Returns the BURN (Burn note) note script root.
fn burn_root() -> Word {
    BURN_SCRIPT.root()
}

// WELL KNOWN NOTE
// ================================================================================================

/// The enum holding the types of basic well-known notes provided by the `miden-lib`.
pub enum WellKnownNote {
    P2ID,
    P2IDE,
    SWAP,
    MINT,
    BURN,
}

impl WellKnownNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of inputs of the P2ID note.
    const P2ID_NUM_INPUTS: usize = 2;

    /// Expected number of inputs of the P2IDE note.
    const P2IDE_NUM_INPUTS: usize = 4;

    /// Expected number of inputs of the SWAP note.
    const SWAP_NUM_INPUTS: usize = 10;

    /// Expected number of inputs of the MINT note (private mode).
    const MINT_NUM_INPUTS_PRIVATE: usize = 8;

    /// Expected number of inputs of the BURN note.
    const BURN_NUM_INPUTS: usize = 0;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a [WellKnownNote] instance based on the note script of the provided [Note]. Returns
    /// `None` if the provided note is not a basic well-known note.
    pub fn from_note(note: &Note) -> Option<Self> {
        let note_script_root = note.script().root();

        if note_script_root == p2id_root() {
            return Some(Self::P2ID);
        }
        if note_script_root == p2ide_root() {
            return Some(Self::P2IDE);
        }
        if note_script_root == swap_root() {
            return Some(Self::SWAP);
        }
        if note_script_root == mint_root() {
            return Some(Self::MINT);
        }
        if note_script_root == burn_root() {
            return Some(Self::BURN);
        }

        None
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the expected inputs number of the active note.
    pub fn num_expected_inputs(&self) -> usize {
        match self {
            Self::P2ID => Self::P2ID_NUM_INPUTS,
            Self::P2IDE => Self::P2IDE_NUM_INPUTS,
            Self::SWAP => Self::SWAP_NUM_INPUTS,
            Self::MINT => Self::MINT_NUM_INPUTS_PRIVATE,
            Self::BURN => Self::BURN_NUM_INPUTS,
        }
    }

    /// Returns the note script of the current [WellKnownNote] instance.
    pub fn script(&self) -> NoteScript {
        match self {
            Self::P2ID => p2id(),
            Self::P2IDE => p2ide(),
            Self::SWAP => swap(),
            Self::MINT => mint(),
            Self::BURN => burn(),
        }
    }

    /// Returns the script root of the current [WellKnownNote] instance.
    pub fn script_root(&self) -> Word {
        match self {
            Self::P2ID => p2id_root(),
            Self::P2IDE => p2ide_root(),
            Self::SWAP => swap_root(),
            Self::MINT => mint_root(),
            Self::BURN => burn_root(),
        }
    }

    /// Returns a boolean value indicating whether this [WellKnownNote] is compatible with the
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

    /// Performs the inputs check of the provided well-known note against the target account and the
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
    ///     - check that note inputs have correct number of values.
    ///     - assertion that the account ID provided by the note inputs is equal to the target
    ///       account ID.
    /// - for `P2IDE` note:
    ///     - check that note inputs have correct number of values.
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
            WellKnownNote::P2ID => {
                let input_account_id = parse_p2id_inputs(note.inputs().values())?;

                if input_account_id == target_account_id {
                    Ok(Some(NoteConsumptionStatus::ConsumableWithAuthorization))
                } else {
                    Ok(Some(NoteConsumptionStatus::NeverConsumable("account ID provided to the P2ID note inputs doesn't match the target account ID".into())))
                }
            },
            WellKnownNote::P2IDE => {
                let (receiver_account_id, reclaim_height, timelock_height) =
                    parse_p2ide_inputs(note.inputs().values())?;

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
                // inputs), then this account cannot consume the note
                } else {
                    Ok(Some(NoteConsumptionStatus::NeverConsumable(
                        "target account of the transaction does not match neither the receiver account specified by the P2IDE inputs, nor the sender account".into()
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

/// Returns the receiver account ID parsed from the provided P2ID note inputs.
///
/// # Errors
///
/// Returns an error if:
/// - the length of the provided note inputs array is not equal to the expected inputs number of the
///   P2ID note.
/// - first two elements of the note inputs array does not form the valid account ID.
fn parse_p2id_inputs(note_inputs: &[Felt]) -> Result<AccountId, StaticAnalysisError> {
    if note_inputs.len() != WellKnownNote::P2ID.num_expected_inputs() {
        return Err(StaticAnalysisError::new(format!(
            "P2ID note should have {} inputs, but {} was provided",
            WellKnownNote::P2ID.num_expected_inputs(),
            note_inputs.len()
        )));
    }

    try_read_account_id_from_inputs(note_inputs)
}

/// Returns the receiver account ID, reclaim height and timelock height parsed from the provided
/// P2IDE note inputs.
///
/// # Errors
///
/// Returns an error if:
/// - the length of the provided note inputs array is not equal to the expected inputs number of the
///   P2IDE note.
/// - first two elements of the note inputs array does not form the valid account ID.
/// - third note inputs array element (reclaim height) is not a valid u32 value.
/// - fourth note inputs array element (timelock height) is not a valid u32 value.
fn parse_p2ide_inputs(note_inputs: &[Felt]) -> Result<(AccountId, u32, u32), StaticAnalysisError> {
    if note_inputs.len() != WellKnownNote::P2IDE.num_expected_inputs() {
        return Err(StaticAnalysisError::new(format!(
            "P2IDE note should have {} inputs, but {} was provided",
            WellKnownNote::P2IDE.num_expected_inputs(),
            note_inputs.len()
        )));
    }

    let receiver_account_id = try_read_account_id_from_inputs(note_inputs)?;

    let reclaim_height_u64 = note_inputs[2].as_canonical_u64();
    let reclaim_height: u32 = reclaim_height_u64
        .try_into()
        .map_err(|_err| StaticAnalysisError::new("reclaim block height should be a u32"))?;

    let timelock_height_u64 = note_inputs[3].as_canonical_u64();
    let timelock_height: u32 = timelock_height_u64
        .try_into()
        .map_err(|_err| StaticAnalysisError::new("timelock block height should be a u32"))?;

    Ok((receiver_account_id, reclaim_height, timelock_height))
}

/// Reads the account ID from the first two note input values.
///
/// Returns None if the note input values used to construct the account ID are invalid.
fn try_read_account_id_from_inputs(note_inputs: &[Felt]) -> Result<AccountId, StaticAnalysisError> {
    if note_inputs.len() < 2 {
        return Err(StaticAnalysisError::new(format!(
            "P2ID and P2IDE notes should have at least 2 note inputs, but {} was provided",
            note_inputs.len()
        )));
    }

    AccountId::try_from([note_inputs[1], note_inputs[0]]).map_err(|source| {
        StaticAnalysisError::with_source(
            "failed to create an account ID from the first two note inputs",
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
