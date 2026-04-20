extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountComponent,
    AccountId,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
use miden_protocol::errors::AccountIdError;
use miden_standards::account::access::Ownable2Step;
use miden_standards::account::faucets::{FungibleFaucetError, TokenMetadata};
use miden_standards::account::mint_policies::OwnerControlled;
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
    create_claim_note,
};

// CONSTANTS
// ================================================================================================
// Include the generated agglayer constants
include!(concat!(env!("OUT_DIR"), "/agglayer_constants.rs"));

// AGGLAYER FAUCET STRUCT
// ================================================================================================

/// An [`AccountComponent`] implementing the AggLayer Faucet.
///
/// It re-exports `mint_and_send` (network fungible faucet) and `burn` (basic fungible faucet)
/// from the agglayer library. Conversion metadata (origin address, origin network, scale,
/// metadata hash) is held by the bridge, not the faucet — see
/// [`AggLayerBridge`] and the `faucet_metadata_map` populated on registration.
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Stores [`TokenMetadata`].
///
/// ## Required Companion Components
///
/// This component re-exports `network_fungible::mint_and_send`, which requires:
/// - [`Ownable2Step`]: Provides ownership data (bridge account ID as owner).
/// - [`miden_standards::account::mint_policies::OwnerControlled`]: Provides mint policy management.
///
/// These must be added as separate components when building the faucet account.
#[derive(Debug, Clone)]
pub struct AggLayerFaucet {
    metadata: TokenMetadata,
}

impl AggLayerFaucet {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new AggLayer faucet component from the given configuration.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The decimals parameter exceeds maximum value of [`TokenMetadata::MAX_DECIMALS`].
    /// - The max supply exceeds maximum possible amount for a fungible asset.
    /// - The token supply exceeds the max supply.
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        token_supply: Felt,
    ) -> Result<Self, FungibleFaucetError> {
        let metadata = TokenMetadata::with_supply(symbol, decimals, max_supply, token_supply)?;
        Ok(Self { metadata })
    }

    /// Sets the token supply for an existing faucet (e.g. for testing scenarios).
    ///
    /// # Errors
    /// Returns an error if the token supply exceeds the max supply.
    pub fn with_token_supply(mut self, token_supply: Felt) -> Result<Self, FungibleFaucetError> {
        self.metadata = self.metadata.with_token_supply(token_supply)?;
        Ok(self)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Storage slot name for [`TokenMetadata`].
    pub fn metadata_slot() -> &'static StorageSlotName {
        TokenMetadata::metadata_slot()
    }

    /// Storage slot name for the owner account ID (bridge), provided by the
    /// [`Ownable2Step`] companion component.
    pub fn owner_config_slot() -> &'static StorageSlotName {
        Ownable2Step::slot_name()
    }

    /// Extracts the token metadata from the corresponding storage slot of the provided account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerFaucet`] account.
    pub fn metadata(faucet_account: &Account) -> Result<TokenMetadata, AgglayerFaucetError> {
        // check that the provided account is a faucet account
        Self::assert_faucet_account(faucet_account)?;

        let metadata_word = faucet_account
            .storage()
            .get_item(TokenMetadata::metadata_slot())
            .expect("should be able to read metadata slot");
        TokenMetadata::try_from(metadata_word).map_err(AgglayerFaucetError::FungibleFaucetError)
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
            TokenMetadata::metadata_slot(),
            Ownable2Step::slot_name(),
            OwnerControlled::active_policy_proc_root_slot(),
            OwnerControlled::allowed_policy_proc_roots_slot(),
            OwnerControlled::policy_authority_slot(),
        ]
    }
}

impl From<AggLayerFaucet> for AccountComponent {
    fn from(faucet: AggLayerFaucet) -> Self {
        let metadata_slot = StorageSlot::from(faucet.metadata);
        agglayer_faucet_component(vec![metadata_slot])
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
    let metadata = AccountComponentMetadata::new("agglayer::faucet", [AccountType::FungibleFaucet])
        .with_description("AggLayer faucet component");

    AccountComponent::new(library, storage_slots, metadata).expect(
        "agglayer_faucet component should satisfy the requirements of a valid account component",
    )
}
