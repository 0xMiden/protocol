use alloc::boxed::Box;
use alloc::string::ToString;
use core::error::Error;

use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};

mod burn;
pub use burn::BurnNote;

mod faucet_policy_action;
pub use faucet_policy_action::{FaucetPolicyAction, FaucetPolicyActionNote};

mod fee_sponsorship;
pub use fee_sponsorship::{FeeSponsorshipNote, FeeSponsorshipNoteStorage};

mod execution_hint;
pub use execution_hint::NoteExecutionHint;

mod file;
pub use file::{NoteFile, NoteSyncHint};

mod mint;
pub use mint::{MintNote, MintNoteStorage};

mod owner_action;
pub use owner_action::{OwnerAction, OwnerActionNote};

mod p2id;
pub use p2id::{P2idNote, P2idNoteStorage};

mod p2ide;
pub use p2ide::{P2ideNote, P2ideNoteStorage};

mod pause_action;
pub use pause_action::{PauseAction, PauseActionNote};

mod pswap;
pub use pswap::{PswapNote, PswapNoteAttachment, PswapNoteStorage};

mod rbac_action;
pub use rbac_action::{RbacAction, RbacActionNote};

mod swap;
pub use swap::{SwapNote, SwapNoteStorage, SwapPayback, payback_serial_from_swap};

mod tx_fee;
pub use tx_fee::TxFeeNote;

mod network_account_target;
pub use network_account_target::{NetworkAccountTarget, NetworkAccountTargetError};

mod network_note;
pub use network_note::{AccountTargetNetworkNote, NetworkNoteExt};

mod standard_note_attachment;
use miden_protocol::errors::NoteError;
pub use standard_note_attachment::StandardNoteAttachment;
// STANDARD NOTE
// ================================================================================================

/// The enum holding the types of standard notes provided by `miden-standards`.
#[allow(non_camel_case_types)]
pub enum StandardNote {
    P2ID,
    P2IDE,
    SWAP,
    PSWAP,
    MINT,
    BURN,
    FAUCET_POLICY_ACTION,
    PAUSE_ACTION,
    OWNER_ACTION,
    RBAC_ACTION,
    FEE_SPONSORSHIP,
    TX_FEE,
}

impl StandardNote {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a [`StandardNote`] instance based on the provided [`NoteScript`]. Returns `None`
    /// if the provided script does not match any standard note script.
    pub fn from_script(script: &NoteScript) -> Option<Self> {
        Self::from_script_root(script.root())
    }

    /// Returns a [`StandardNote`] instance based on the provided script root. Returns `None` if
    /// the provided root does not match any standard note script.
    pub fn from_script_root(root: NoteScriptRoot) -> Option<Self> {
        if root == P2idNote::script_root() {
            return Some(Self::P2ID);
        }
        if root == P2ideNote::script_root() {
            return Some(Self::P2IDE);
        }
        if root == SwapNote::script_root() {
            return Some(Self::SWAP);
        }
        if root == PswapNote::script_root() {
            return Some(Self::PSWAP);
        }
        if root == MintNote::script_root() {
            return Some(Self::MINT);
        }
        if root == BurnNote::script_root() {
            return Some(Self::BURN);
        }
        if root == FaucetPolicyActionNote::script_root() {
            return Some(Self::FAUCET_POLICY_ACTION);
        }
        if root == PauseActionNote::script_root() {
            return Some(Self::PAUSE_ACTION);
        }
        if root == OwnerActionNote::script_root() {
            return Some(Self::OWNER_ACTION);
        }
        if root == RbacActionNote::script_root() {
            return Some(Self::RBAC_ACTION);
        }
        if root == FeeSponsorshipNote::script_root() {
            return Some(Self::FEE_SPONSORSHIP);
        }
        if root == TxFeeNote::script_root() {
            return Some(Self::TX_FEE);
        }

        None
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the name of this [`StandardNote`] variant as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::P2ID => "P2ID",
            Self::P2IDE => "P2IDE",
            Self::SWAP => "SWAP",
            Self::PSWAP => "PSWAP",
            Self::MINT => "MINT",
            Self::BURN => "BURN",
            Self::FAUCET_POLICY_ACTION => "FAUCET_POLICY_ACTION",
            Self::PAUSE_ACTION => "PAUSE_ACTION",
            Self::OWNER_ACTION => "OWNER_ACTION",
            Self::RBAC_ACTION => "RBAC_ACTION",
            Self::FEE_SPONSORSHIP => "FEE_SPONSORSHIP",
            Self::TX_FEE => "TX_FEE",
        }
    }

    /// Returns the expected number of storage items of the active note.
    pub fn expected_num_storage_items(&self) -> usize {
        match self {
            Self::P2ID => P2idNote::NUM_STORAGE_ITEMS,
            Self::P2IDE => P2ideNote::NUM_STORAGE_ITEMS,
            Self::SWAP => SwapNote::NUM_STORAGE_ITEMS,
            Self::PSWAP => PswapNote::NUM_STORAGE_ITEMS,
            Self::MINT => MintNote::NUM_STORAGE_ITEMS_PRIVATE,
            Self::BURN => BurnNote::NUM_STORAGE_ITEMS,
            Self::FAUCET_POLICY_ACTION => FaucetPolicyActionNote::NUM_STORAGE_ITEMS,
            Self::PAUSE_ACTION => PauseActionNote::NUM_STORAGE_ITEMS,
            // OwnerAction storage is variable per action; this returns the upper bound.
            Self::OWNER_ACTION => OwnerActionNote::MAX_NUM_STORAGE_ITEMS,
            // RbacAction storage is variable per action; this returns the upper bound.
            Self::RBAC_ACTION => RbacActionNote::MAX_NUM_STORAGE_ITEMS,
            Self::FEE_SPONSORSHIP => FeeSponsorshipNote::NUM_STORAGE_ITEMS,
            Self::TX_FEE => TxFeeNote::NUM_STORAGE_ITEMS,
        }
    }

    /// Returns the note script of the current [StandardNote] instance.
    pub fn script(&self) -> NoteScript {
        match self {
            Self::P2ID => P2idNote::script(),
            Self::P2IDE => P2ideNote::script(),
            Self::SWAP => SwapNote::script(),
            Self::PSWAP => PswapNote::script(),
            Self::MINT => MintNote::script(),
            Self::BURN => BurnNote::script(),
            Self::FAUCET_POLICY_ACTION => FaucetPolicyActionNote::script(),
            Self::PAUSE_ACTION => PauseActionNote::script(),
            Self::OWNER_ACTION => OwnerActionNote::script(),
            Self::RBAC_ACTION => RbacActionNote::script(),
            Self::FEE_SPONSORSHIP => FeeSponsorshipNote::script(),
            Self::TX_FEE => TxFeeNote::script(),
        }
    }

    /// Returns the script root of the current [StandardNote] instance.
    pub fn script_root(&self) -> NoteScriptRoot {
        match self {
            Self::P2ID => P2idNote::script_root(),
            Self::P2IDE => P2ideNote::script_root(),
            Self::SWAP => SwapNote::script_root(),
            Self::PSWAP => PswapNote::script_root(),
            Self::MINT => MintNote::script_root(),
            Self::BURN => BurnNote::script_root(),
            Self::FAUCET_POLICY_ACTION => FaucetPolicyActionNote::script_root(),
            Self::PAUSE_ACTION => PauseActionNote::script_root(),
            Self::OWNER_ACTION => OwnerActionNote::script_root(),
            Self::RBAC_ACTION => RbacActionNote::script_root(),
            Self::FEE_SPONSORSHIP => FeeSponsorshipNote::script_root(),
            Self::TX_FEE => TxFeeNote::script_root(),
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
    ///     - check that the target account is either the receiver account or the reclaimer account.
    ///     - check that depending on whether the target account is reclaimer or receiver, it could
    ///       be either consumed, or consumed after timelock height, or consumed after reclaim
    ///       height.
    /// - for `TX_FEE` note:
    ///     - check that note storage is empty; the note is otherwise consumable by any account.
    fn is_consumable_inner(
        &self,
        note: &Note,
        target_account_id: AccountId,
        block_ref: BlockNumber,
    ) -> Result<Option<NoteConsumptionStatus>, NoteError> {
        match self {
            StandardNote::P2ID => {
                let input_account_id = P2idNoteStorage::try_from(note.storage().items())
                    .map_err(|e| NoteError::other_with_source("invalid P2ID note storage", e))?;

                if input_account_id.target() == target_account_id {
                    Ok(Some(NoteConsumptionStatus::ConsumableWithAuthorization))
                } else {
                    Ok(Some(NoteConsumptionStatus::NeverConsumable("account ID provided to the P2ID note storage doesn't match the target account ID".into())))
                }
            },
            StandardNote::P2IDE => {
                let storage = P2ideNoteStorage::try_from(note.storage().items())
                    .map_err(|e| NoteError::other_with_source("invalid P2IDE note storage", e))?;

                let reclaimer_account_id = storage.reclaimer();
                let receiver_account_id = storage.target();

                let current_block_height = block_ref.as_u32();
                let reclaim_height = storage.reclaim_height().unwrap_or_default().as_u32();
                let timelock_height = storage.timelock_height().unwrap_or_default().as_u32();

                // block height after which the reclaimer account can consume the note
                let consumable_after = reclaim_height.max(timelock_height);

                // handle the case when the target account of the transaction is the reclaimer
                if target_account_id == reclaimer_account_id {
                    // For the reclaimer, the current block height needs to have reached both
                    // reclaim and timelock height to be consumable.
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
                // if the target account is neither the reclaimer nor the receiver (from the
                // note's storage), then this account cannot consume the note
                } else {
                    Ok(Some(NoteConsumptionStatus::NeverConsumable(
            "target account of the transaction does not match neither the receiver account specified by the P2IDE storage, nor the reclaimer account".into()
        )))
                }
            },

            // TX_FEE notes carry no target restriction: any account can consume them, as long as
            // the note carries no storage items (the note script rejects any other
            // storage shape).
            StandardNote::TX_FEE => {
                if usize::from(note.storage().num_items()) != TxFeeNote::NUM_STORAGE_ITEMS {
                    Ok(Some(NoteConsumptionStatus::NeverConsumable(
                        "TX_FEE note carries unexpected storage items".into(),
                    )))
                } else {
                    Ok(Some(NoteConsumptionStatus::ConsumableWithAuthorization))
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

/// Decodes an optional block height stored as a single storage item, where zero encodes `None`.
///
/// `error_msg` names the field being decoded so that a caller can tell the heights apart.
pub(crate) fn decode_optional_block_height(
    item: Felt,
    error_msg: &'static str,
) -> Result<Option<BlockNumber>, NoteError> {
    if item == Felt::ZERO {
        return Ok(None);
    }

    let height: u32 = item
        .as_canonical_u64()
        .try_into()
        .map_err(|e| NoteError::other_with_source(error_msg, e))?;

    Ok(Some(BlockNumber::from(height)))
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
