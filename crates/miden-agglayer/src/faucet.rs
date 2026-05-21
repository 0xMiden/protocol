extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountComponent, AccountId, StorageSlot, StorageSlotName};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::errors::AccountIdError;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{FungibleFaucet, FungibleFaucetError, TokenName};
use miden_standards::account::policies::TokenPolicyManager;
use miden_standards::note::{BurnNote, MintNote};
use thiserror::Error;

use super::agglayer_faucet_component_library;
pub use crate::{
    AggLayerBridge,
    B2AggNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    EthAddress,
    EthAmount,
    EthAmountError,
    EthEmbeddedAccountId,
    ExitRoot,
    GlobalIndex,
    GlobalIndexError,
    LeafData,
    MetadataHash,
    ProofData,
    SmtNode,
    UpdateGerNote,
};

// CONSTANTS
// ================================================================================================
// Include the generated agglayer constants
include!(concat!(env!("OUT_DIR"), "/agglayer_constants.rs"));

// AGGLAYER FAUCET STRUCT
// ================================================================================================

/// An [`AccountComponent`] implementing the AggLayer Faucet.
///
/// It re-exports `mint_and_send` and `receive_and_burn` from the agglayer faucet library.
/// Conversion metadata (origin address, origin network, scale, metadata hash) is held by the
/// bridge, not the faucet — see
/// [`AggLayerBridge`] and the `faucet_metadata_map` populated on registration.
///
/// ## Storage Layout
///
/// - All [`FungibleFaucet`] storage slots (token config + name + mutability + description + logo
///   URI + external link). Conversion metadata is no longer stored on the faucet; the bridge holds
///   it in `faucet_metadata_map`.
///
/// ## Required Companion Components
///
/// This component re-exports `fungible::mint_and_send`, which requires:
/// - [`Ownable2Step`]: Provides ownership data (bridge account ID as owner).
/// - [`miden_standards::account::policies::TokenPolicyManager`]: Provides mint and burn policy
///   management.
///
/// These must be added as separate components when building the faucet account.
#[derive(Debug, Clone)]
pub struct AggLayerFaucet {
    faucet: FungibleFaucet,
}

impl AggLayerFaucet {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new AggLayer faucet component from the given configuration.
    ///
    /// The faucet's display name is derived from the symbol (an AggLayer faucet is identified by
    /// its symbol; the human-readable name is not used in the bridge protocol).
    ///
    /// # Errors
    /// Returns an error if:
    /// - The decimals parameter exceeds maximum value of [`FungibleFaucet::MAX_DECIMALS`].
    /// - The max supply exceeds maximum possible amount for a fungible asset.
    /// - The token supply exceeds the max supply.
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        token_supply: Felt,
    ) -> Result<Self, FungibleFaucetError> {
        // Use the symbol as the display name; AggLayer faucets do not use a separate token name.
        let name = TokenName::new(symbol.to_string().as_str())
            .expect("symbol fits within token name capacity");
        let max_supply_amount = AssetAmount::try_from(max_supply).map_err(|_| {
            FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply.as_canonical_u64(),
                max: AssetAmount::MAX.as_u64(),
            }
        })?;
        let token_supply_amount = AssetAmount::try_from(token_supply).map_err(|_| {
            FungibleFaucetError::MaxSupplyTooLarge {
                actual: token_supply.as_canonical_u64(),
                max: AssetAmount::MAX.as_u64(),
            }
        })?;
        let faucet = FungibleFaucet::builder()
            .name(name)
            .symbol(symbol)
            .decimals(decimals)
            .max_supply(max_supply_amount)
            .token_supply(token_supply_amount)
            .build()?;
        Ok(Self { faucet })
    }

    /// Sets the token supply for an existing faucet (e.g. for testing scenarios).
    ///
    /// # Errors
    /// Returns an error if the token supply exceeds the max supply.
    pub fn with_token_supply(mut self, token_supply: Felt) -> Result<Self, FungibleFaucetError> {
        let token_supply_amount = AssetAmount::try_from(token_supply).map_err(|_| {
            FungibleFaucetError::MaxSupplyTooLarge {
                actual: token_supply.as_canonical_u64(),
                max: AssetAmount::MAX.as_u64(),
            }
        })?;
        self.faucet = self.faucet.with_token_supply(token_supply_amount)?;
        Ok(self)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Storage slot name for the token config word
    /// `[token_supply, max_supply, decimals, token_symbol]`.
    pub fn token_config_slot() -> &'static StorageSlotName {
        FungibleFaucet::token_config_slot()
    }

    /// Storage slot name for the owner account ID (bridge), provided by the
    /// [`Ownable2Step`] companion component.
    pub fn owner_config_slot() -> &'static StorageSlotName {
        Ownable2Step::slot_name()
    }

    // ALLOWED NOTES
    // --------------------------------------------------------------------------------------------

    /// Returns the set of input-note script roots that AggLayer faucet accounts accept.
    ///
    /// The faucet's [`AuthNetworkAccount`] component is initialized with this allowlist so only
    /// MINT and BURN notes can drive the faucet.
    ///
    /// [`AuthNetworkAccount`]: miden_standards::account::auth::AuthNetworkAccount
    pub fn allowed_notes() -> BTreeSet<NoteScriptRoot> {
        BTreeSet::from([MintNote::script_root(), BurnNote::script_root()])
    }

    /// Extracts the underlying [`FungibleFaucet`] component (which holds the token metadata)
    /// from the storage slots of the provided account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerFaucet`] account.
    pub fn try_faucet_from_account(
        faucet_account: &Account,
    ) -> Result<FungibleFaucet, AgglayerFaucetError> {
        // check that the provided account is a faucet account
        Self::assert_faucet_account(faucet_account)?;

        FungibleFaucet::try_from(faucet_account.storage())
            .map_err(AgglayerFaucetError::FungibleFaucetError)
    }

    /// Extracts the bridge account ID from the [`Ownable2Step`] owner config storage slot
    /// of the provided account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerFaucet`] account.
    pub fn owner_account_id(faucet_account: &Account) -> Result<AccountId, AgglayerFaucetError> {
        // check that the provided account is a faucet account
        Self::assert_faucet_account(faucet_account)?;

        let ownership = Ownable2Step::try_from_storage(faucet_account.storage())
            .map_err(AgglayerFaucetError::Ownable2StepError)?;
        ownership.owner().ok_or(AgglayerFaucetError::OwnershipRenounced)
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Checks that the provided account is an [`AggLayerFaucet`] account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account does not have all AggLayer Faucet specific storage slots.
    /// - the provided account does not have all AggLayer Faucet specific procedures.
    fn assert_faucet_account(account: &Account) -> Result<(), AgglayerFaucetError> {
        // check that the storage slots are as expected
        Self::assert_storage_slots(account)?;

        // check that the procedure roots are as expected
        Self::assert_code_commitment(account)?;

        Ok(())
    }

    /// Checks that the provided account has all storage slots required for the [`AggLayerFaucet`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - provided account does not have all AggLayer Faucet specific storage slots).
    fn assert_storage_slots(account: &Account) -> Result<(), AgglayerFaucetError> {
        // get the storage slot names of the provided account
        let account_storage_slot_names: Vec<&StorageSlotName> = account
            .storage()
            .slots()
            .iter()
            .map(|storage_slot| storage_slot.name())
            .collect::<Vec<&StorageSlotName>>();

        // check that all bridge specific storage slots are presented in the provided account
        let are_slots_present = Self::slot_names()
            .iter()
            .all(|slot_name| account_storage_slot_names.contains(slot_name));
        if !are_slots_present {
            return Err(AgglayerFaucetError::StorageSlotsMismatch);
        }

        Ok(())
    }

    /// Checks that the code commitment of the provided account matches the code commitment of the
    /// [`AggLayerFaucet`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the code commitment of the provided account does not match the code commitment of the
    ///   [`AggLayerFaucet`].
    fn assert_code_commitment(account: &Account) -> Result<(), AgglayerFaucetError> {
        if FAUCET_CODE_COMMITMENT != account.code().commitment() {
            return Err(AgglayerFaucetError::CodeCommitmentMismatch);
        }

        Ok(())
    }

    /// Returns a vector of all [`AggLayerFaucet`] storage slot names.
    fn slot_names() -> Vec<&'static StorageSlotName> {
        vec![
            FungibleFaucet::token_config_slot(),
            Ownable2Step::slot_name(),
            Authority::authority_slot(),
            TokenPolicyManager::active_mint_policy_slot(),
            TokenPolicyManager::active_burn_policy_slot(),
            TokenPolicyManager::allowed_mint_policies_slot(),
            TokenPolicyManager::allowed_burn_policies_slot(),
            TokenPolicyManager::allowed_send_policies_slot(),
            TokenPolicyManager::allowed_receive_policies_slot(),
        ]
    }
}

impl From<AggLayerFaucet> for AccountComponent {
    fn from(agglayer_faucet: AggLayerFaucet) -> Self {
        // Bring in all of the FungibleFaucet's storage slots (token config + name +
        // mutability + description + logo URI + external link).
        agglayer_faucet_component(agglayer_faucet.faucet.into_storage_slots())
    }
}

// AGGLAYER FAUCET ERROR
// ================================================================================================

/// AggLayer Faucet related errors.
#[derive(Debug, Error)]
pub enum AgglayerFaucetError {
    #[error(
        "provided account does not have storage slots required for the AggLayer Faucet account"
    )]
    StorageSlotsMismatch,
    #[error("provided account does not have procedures required for the AggLayer Faucet account")]
    CodeCommitmentMismatch,
    #[error("fungible faucet error")]
    FungibleFaucetError(#[source] FungibleFaucetError),
    #[error("account ID error")]
    AccountIdError(#[source] AccountIdError),
    #[error("ownable2step error")]
    Ownable2StepError(#[source] miden_standards::account::access::Ownable2StepError),
    #[error("faucet ownership has been renounced")]
    OwnershipRenounced,
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates an Agglayer Faucet component with the specified storage slots.
fn agglayer_faucet_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_faucet_component_library();
    let metadata = AccountComponentMetadata::new("agglayer::faucet")
        .with_description("AggLayer faucet component");

    AccountComponent::new(library, storage_slots, metadata).expect(
        "agglayer_faucet component should satisfy the requirements of a valid account component",
    )
}
