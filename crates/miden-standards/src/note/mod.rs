use alloc::boxed::Box;
use alloc::string::ToString;
use core::error::Error;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS};

use self::config::{
    AllowlistConfigNote,
    BlocklistConfigNote,
    ConstantFeePolicyConfigNote,
    FaucetMetadataConfigNote,
    FaucetPolicyConfigNote,
    MinBurnAmountConfigNote,
    NetworkAccountConfigNote,
    OwnerConfigNote,
    PauseConfigNote,
    RbacConfigNote,
};

pub mod config;
pub mod costs;

mod burn;
pub use burn::BurnNote;

mod fee_sponsorship;
pub use fee_sponsorship::{FeeSponsorshipNote, FeeSponsorshipNoteStorage};

mod execution_hint;
pub use execution_hint::NoteExecutionHint;

mod file;
pub use file::{NoteFile, NoteSyncHint};

mod mint;
pub use mint::{MintNote, MintNoteStorage};

mod p2id;
pub use p2id::{P2idNote, P2idNoteStorage};

mod p2ide;
pub use p2ide::{P2ideNote, P2ideNoteStorage};

mod pswap;
pub use pswap::{PswapNote, PswapNoteAttachment, PswapNoteStorage};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardNote {
    P2ID,
    P2IDE,
    SWAP,
    PSWAP,
    MINT,
    BURN,
    CONSTANT_FEE_POLICY_CONFIG,
    FAUCET_POLICY_CONFIG,
    FAUCET_METADATA_CONFIG,
    MIN_BURN_AMOUNT_CONFIG,
    ALLOWLIST_CONFIG,
    BLOCKLIST_CONFIG,
    PAUSE_CONFIG,
    OWNER_CONFIG,
    RBAC_CONFIG,
    NETWORK_ACCOUNT_CONFIG,
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
        if root == ConstantFeePolicyConfigNote::script_root() {
            return Some(Self::CONSTANT_FEE_POLICY_CONFIG);
        }
        if root == FaucetPolicyConfigNote::script_root() {
            return Some(Self::FAUCET_POLICY_CONFIG);
        }
        if root == FaucetMetadataConfigNote::script_root() {
            return Some(Self::FAUCET_METADATA_CONFIG);
        }
        if root == MinBurnAmountConfigNote::script_root() {
            return Some(Self::MIN_BURN_AMOUNT_CONFIG);
        }
        if root == AllowlistConfigNote::script_root() {
            return Some(Self::ALLOWLIST_CONFIG);
        }
        if root == BlocklistConfigNote::script_root() {
            return Some(Self::BLOCKLIST_CONFIG);
        }
        if root == PauseConfigNote::script_root() {
            return Some(Self::PAUSE_CONFIG);
        }
        if root == OwnerConfigNote::script_root() {
            return Some(Self::OWNER_CONFIG);
        }
        if root == RbacConfigNote::script_root() {
            return Some(Self::RBAC_CONFIG);
        }
        if root == NetworkAccountConfigNote::script_root() {
            return Some(Self::NETWORK_ACCOUNT_CONFIG);
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
            Self::CONSTANT_FEE_POLICY_CONFIG => "CONSTANT_FEE_POLICY_CONFIG",
            Self::FAUCET_POLICY_CONFIG => "FAUCET_POLICY_CONFIG",
            Self::FAUCET_METADATA_CONFIG => "FAUCET_METADATA_CONFIG",
            Self::MIN_BURN_AMOUNT_CONFIG => "MIN_BURN_AMOUNT_CONFIG",
            Self::ALLOWLIST_CONFIG => "ALLOWLIST_CONFIG",
            Self::BLOCKLIST_CONFIG => "BLOCKLIST_CONFIG",
            Self::PAUSE_CONFIG => "PAUSE_CONFIG",
            Self::OWNER_CONFIG => "OWNER_CONFIG",
            Self::RBAC_CONFIG => "RBAC_CONFIG",
            Self::NETWORK_ACCOUNT_CONFIG => "NETWORK_ACCOUNT_CONFIG",
            Self::FEE_SPONSORSHIP => "FEE_SPONSORSHIP",
            Self::TX_FEE => "TX_FEE",
        }
    }

    /// Returns `true` if `num_storage_items` is a valid number of storage items for this kind of
    /// note.
    ///
    /// Several note kinds accept more than one storage size, so no single expected size can be
    /// derived from the script root alone: a MINT note holds exactly
    /// [`MintNote::NUM_STORAGE_ITEMS_PRIVATE`] items when it creates a private output note and at
    /// least [`MintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC`] when it creates a public one, and the
    /// config notes size their storage per action. This predicate mirrors the sizes each note
    /// script accepts, and should be used instead of comparing against a single constant.
    pub fn accepts_num_storage_items(&self, num_storage_items: usize) -> bool {
        match self {
            Self::P2ID => num_storage_items == P2idNote::NUM_STORAGE_ITEMS,
            Self::P2IDE => num_storage_items == P2ideNote::NUM_STORAGE_ITEMS,
            Self::SWAP => num_storage_items == SwapNote::NUM_STORAGE_ITEMS,
            Self::PSWAP => num_storage_items == PswapNote::NUM_STORAGE_ITEMS,
            // A MINT note creating a private output note holds exactly 13 items, while one
            // creating a public output note holds at least 20 and grows with the storage of the
            // output note recipient.
            Self::MINT => {
                num_storage_items == MintNote::NUM_STORAGE_ITEMS_PRIVATE
                    || (MintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC..=MAX_NOTE_STORAGE_ITEMS)
                        .contains(&num_storage_items)
            },
            Self::BURN => num_storage_items == BurnNote::NUM_STORAGE_ITEMS,
            Self::CONSTANT_FEE_POLICY_CONFIG => {
                num_storage_items == ConstantFeePolicyConfigNote::NUM_STORAGE_ITEMS
            },
            Self::FAUCET_POLICY_CONFIG => {
                num_storage_items == FaucetPolicyConfigNote::NUM_STORAGE_ITEMS
            },
            // FaucetMetadataConfig storage is variable per action: `SetMaxSupply` uses the
            // minimum, the string-setting actions use the maximum.
            Self::FAUCET_METADATA_CONFIG => {
                num_storage_items == FaucetMetadataConfigNote::MIN_NUM_STORAGE_ITEMS
                    || num_storage_items == FaucetMetadataConfigNote::MAX_NUM_STORAGE_ITEMS
            },
            Self::MIN_BURN_AMOUNT_CONFIG => {
                num_storage_items == MinBurnAmountConfigNote::NUM_STORAGE_ITEMS
            },
            Self::ALLOWLIST_CONFIG => num_storage_items == AllowlistConfigNote::NUM_STORAGE_ITEMS,
            Self::BLOCKLIST_CONFIG => num_storage_items == BlocklistConfigNote::NUM_STORAGE_ITEMS,
            Self::PAUSE_CONFIG => num_storage_items == PauseConfigNote::NUM_STORAGE_ITEMS,
            // OwnerConfig storage is variable per action: `TransferOwnership` uses the maximum,
            // `AcceptOwnership` / `RenounceOwnership` the minimum. No size in between is valid.
            Self::OWNER_CONFIG => {
                num_storage_items == OwnerConfigNote::MIN_NUM_STORAGE_ITEMS
                    || num_storage_items == OwnerConfigNote::MAX_NUM_STORAGE_ITEMS
            },
            // RbacConfig storage is variable per action, and every size between its bounds is
            // used by one of them.
            Self::RBAC_CONFIG => (RbacConfigNote::MIN_NUM_STORAGE_ITEMS
                ..=RbacConfigNote::MAX_NUM_STORAGE_ITEMS)
                .contains(&num_storage_items),
            Self::NETWORK_ACCOUNT_CONFIG => {
                num_storage_items == NetworkAccountConfigNote::NUM_STORAGE_ITEMS
            },
            Self::FEE_SPONSORSHIP => num_storage_items == FeeSponsorshipNote::NUM_STORAGE_ITEMS,
            Self::TX_FEE => num_storage_items == TxFeeNote::NUM_STORAGE_ITEMS,
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
            Self::CONSTANT_FEE_POLICY_CONFIG => ConstantFeePolicyConfigNote::script(),
            Self::FAUCET_POLICY_CONFIG => FaucetPolicyConfigNote::script(),
            Self::FAUCET_METADATA_CONFIG => FaucetMetadataConfigNote::script(),
            Self::MIN_BURN_AMOUNT_CONFIG => MinBurnAmountConfigNote::script(),
            Self::ALLOWLIST_CONFIG => AllowlistConfigNote::script(),
            Self::BLOCKLIST_CONFIG => BlocklistConfigNote::script(),
            Self::PAUSE_CONFIG => PauseConfigNote::script(),
            Self::OWNER_CONFIG => OwnerConfigNote::script(),
            Self::RBAC_CONFIG => RbacConfigNote::script(),
            Self::NETWORK_ACCOUNT_CONFIG => NetworkAccountConfigNote::script(),
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
            Self::CONSTANT_FEE_POLICY_CONFIG => ConstantFeePolicyConfigNote::script_root(),
            Self::FAUCET_POLICY_CONFIG => FaucetPolicyConfigNote::script_root(),
            Self::FAUCET_METADATA_CONFIG => FaucetMetadataConfigNote::script_root(),
            Self::MIN_BURN_AMOUNT_CONFIG => MinBurnAmountConfigNote::script_root(),
            Self::ALLOWLIST_CONFIG => AllowlistConfigNote::script_root(),
            Self::BLOCKLIST_CONFIG => BlocklistConfigNote::script_root(),
            Self::PAUSE_CONFIG => PauseConfigNote::script_root(),
            Self::OWNER_CONFIG => OwnerConfigNote::script_root(),
            Self::RBAC_CONFIG => RbacConfigNote::script_root(),
            Self::NETWORK_ACCOUNT_CONFIG => NetworkAccountConfigNote::script_root(),
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A MINT note holds exactly 13 items when it creates a private output note, and 20 or more
    /// when it creates a public one, so the sizes in between are the only invalid ones below the
    /// protocol limit.
    #[test]
    fn mint_accepts_both_the_private_and_the_public_storage_sizes() {
        for num_items in [MintNote::NUM_STORAGE_ITEMS_PRIVATE, 20, 21, MAX_NOTE_STORAGE_ITEMS] {
            assert!(
                StandardNote::MINT.accepts_num_storage_items(num_items),
                "{num_items} items should be accepted"
            );
        }

        for num_items in [0, 12, 14, 19, MAX_NOTE_STORAGE_ITEMS + 1] {
            assert!(
                !StandardNote::MINT.accepts_num_storage_items(num_items),
                "{num_items} items should be rejected"
            );
        }
    }

    /// The config notes size their storage per action, and the sizes no action uses must be
    /// rejected even when they fall between the bounds.
    #[test]
    fn config_notes_accept_only_the_sizes_their_actions_use() {
        for (note, accepted, rejected) in [
            (StandardNote::OWNER_CONFIG, [1, 3].as_slice(), [0, 2, 4].as_slice()),
            (StandardNote::RBAC_CONFIG, [2, 3, 4].as_slice(), [0, 1, 5].as_slice()),
            (
                StandardNote::FAUCET_METADATA_CONFIG,
                [2, 32].as_slice(),
                [0, 3, 31, 33].as_slice(),
            ),
        ] {
            for &num_items in accepted {
                assert!(
                    note.accepts_num_storage_items(num_items),
                    "{} should accept {num_items} items",
                    note.name()
                );
            }

            for &num_items in rejected {
                assert!(
                    !note.accepts_num_storage_items(num_items),
                    "{} should reject {num_items} items",
                    note.name()
                );
            }
        }
    }

    /// A note of fixed layout accepts its own size and nothing else.
    #[test]
    fn fixed_size_notes_accept_only_their_exact_size() {
        for note in [StandardNote::P2ID, StandardNote::P2IDE, StandardNote::TX_FEE] {
            let num_items = match note {
                StandardNote::P2ID => P2idNote::NUM_STORAGE_ITEMS,
                StandardNote::P2IDE => P2ideNote::NUM_STORAGE_ITEMS,
                _ => TxFeeNote::NUM_STORAGE_ITEMS,
            };

            assert!(note.accepts_num_storage_items(num_items));
            assert!(!note.accepts_num_storage_items(num_items + 1));
        }
    }
}
