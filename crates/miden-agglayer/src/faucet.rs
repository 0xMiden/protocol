extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, FieldElement, Word};
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
use miden_standards::account::faucets::{FungibleFaucetError, TokenMetadata};
use miden_utils_sync::LazyLock;
use thiserror::Error;

use super::agglayer_faucet_component_library;
pub use crate::{
    AggLayerBridge,
    B2AggNote,
    ClaimNoteStorage,
    ConfigAggBridgeNote,
    EthAddressFormat,
    EthAmount,
    EthAmountError,
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

static AGGLAYER_FAUCET_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet")
        .expect("agglayer faucet storage slot name should be valid")
});
static CONVERSION_INFO_1_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet::conversion_info_1")
        .expect("conversion info 1 storage slot name should be valid")
});
static CONVERSION_INFO_2_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::agglayer::faucet::conversion_info_2")
        .expect("conversion info 2 storage slot name should be valid")
});

/// An [`AccountComponent`] implementing the AggLayer Faucet.
///
/// It reexports the procedures from `miden::agglayer::faucet`. When linking against this
/// component, the `agglayer` library must be available to the assembler.
/// The procedures of this component are:
/// - `claim`, which validates a CLAIM note against one of the stored GERs in the bridge.
/// - `asset_to_origin_asset`, which converts an asset to the origin asset (used in FPI from
///   bridge).
/// - `burn`, which burns an asset.
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Stores [`TokenMetadata`].
/// - [`Self::bridge_account_id_slot`]: Stores the AggLayer bridge account ID.
/// - [`Self::conversion_info_1_slot`]: Stores the first 4 felts of the origin token address.
/// - [`Self::conversion_info_2_slot`]: Stores the remaining 5th felt of the origin token address +
///   origin network + scale.
#[derive(Debug, Clone)]
pub struct AggLayerFaucet {
    metadata: TokenMetadata,
    bridge_account_id: AccountId,
    origin_token_address: EthAddressFormat,
    origin_network: u32,
    scale: u8,
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
        bridge_account_id: AccountId,
        origin_token_address: EthAddressFormat,
        origin_network: u32,
        scale: u8,
    ) -> Result<Self, FungibleFaucetError> {
        let metadata = TokenMetadata::with_supply(symbol, decimals, max_supply, token_supply)?;
        Ok(Self {
            metadata,
            bridge_account_id,
            origin_token_address,
            origin_network,
            scale,
        })
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

    /// Storage slot name for the AggLayer bridge account ID.
    pub fn bridge_account_id_slot() -> &'static StorageSlotName {
        &AGGLAYER_FAUCET_SLOT_NAME
    }

    /// Storage slot name for the first 4 felts of the origin token address.
    pub fn conversion_info_1_slot() -> &'static StorageSlotName {
        &CONVERSION_INFO_1_SLOT_NAME
    }

    /// Storage slot name for the 5th felt of the origin token address, origin network, and scale.
    pub fn conversion_info_2_slot() -> &'static StorageSlotName {
        &CONVERSION_INFO_2_SLOT_NAME
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

    /// Extracts the bridge account ID from the corresponding storage slot of the provided account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerFaucet`] account.
    pub fn bridge_account_id(faucet_account: &Account) -> Result<AccountId, AgglayerFaucetError> {
        // check that the provided account is a faucet account
        Self::assert_faucet_account(faucet_account)?;

        let bridge_id_word = faucet_account
            .storage()
            .get_item(&AGGLAYER_FAUCET_SLOT_NAME)
            .expect("should be able to read account ID slot");
        AccountId::try_from([bridge_id_word[3], bridge_id_word[2]])
            .map_err(AgglayerFaucetError::AccountIdError)
    }

    /// Extracts the origin token address from the corresponding storage slot of the provided
    /// account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerFaucet`] account.
    pub fn origin_token_address(
        faucet_account: &Account,
    ) -> Result<EthAddressFormat, AgglayerFaucetError> {
        // check that the provided account is a faucet account
        Self::assert_faucet_account(faucet_account)?;

        let conversion_info_1 = faucet_account
            .storage()
            .get_item(&CONVERSION_INFO_1_SLOT_NAME)
            .expect("should be able to read the first conversion info slot");

        let conversion_info_2 = faucet_account
            .storage()
            .get_item(&CONVERSION_INFO_2_SLOT_NAME)
            .expect("should be able to read the second conversion info slot");

        let addr_bytes_vec = conversion_info_1
            .iter()
            .chain([&conversion_info_2[0]])
            .flat_map(|felt| (felt.as_int() as u32).to_le_bytes())
            .collect::<Vec<u8>>();

        Ok(EthAddressFormat::new(
            addr_bytes_vec
                .try_into()
                .expect("origin token addr vector should consist of exactly 20 bytes"),
        ))
    }

    /// Extracts the origin network ID in form of the u32 from the corresponding storage slot of the
    /// provided account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerFaucet`] account.
    pub fn origin_network(faucet_account: &Account) -> Result<u32, AgglayerFaucetError> {
        // check that the provided account is a faucet account
        Self::assert_faucet_account(faucet_account)?;

        let conversion_info_2 = faucet_account
            .storage()
            .get_item(&CONVERSION_INFO_2_SLOT_NAME)
            .expect("should be able to read the second conversion info slot");

        Ok(conversion_info_2[1].try_into().expect("origin network ID should fit into u32"))
    }

    /// Extracts the scaling factor in form of the u8 from the corresponding storage slot of the
    /// provided account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided account is not an [`AggLayerFaucet`] account.
    pub fn scale(faucet_account: &Account) -> Result<u8, AgglayerFaucetError> {
        // check that the provided account is a faucet account
        Self::assert_faucet_account(faucet_account)?;

        let conversion_info_2 = faucet_account
            .storage()
            .get_item(&CONVERSION_INFO_2_SLOT_NAME)
            .expect("should be able to read the second conversion info slot");

        Ok(conversion_info_2[2].try_into().expect("scaling factor should fit into u8"))
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
            &*AGGLAYER_FAUCET_SLOT_NAME,
            &*CONVERSION_INFO_1_SLOT_NAME,
            &*CONVERSION_INFO_2_SLOT_NAME,
        ]
    }
}

impl From<AggLayerFaucet> for AccountComponent {
    fn from(faucet: AggLayerFaucet) -> Self {
        let metadata_slot = StorageSlot::from(faucet.metadata);

        let bridge_account_id_word = Word::new([
            Felt::ZERO,
            Felt::ZERO,
            faucet.bridge_account_id.suffix(),
            faucet.bridge_account_id.prefix().as_felt(),
        ]);
        let bridge_slot =
            StorageSlot::with_value(AGGLAYER_FAUCET_SLOT_NAME.clone(), bridge_account_id_word);

        let (conversion_slot1_word, conversion_slot2_word) = agglayer_faucet_conversion_slots(
            &faucet.origin_token_address,
            faucet.origin_network,
            faucet.scale,
        );
        let conversion_slot1 =
            StorageSlot::with_value(CONVERSION_INFO_1_SLOT_NAME.clone(), conversion_slot1_word);
        let conversion_slot2 =
            StorageSlot::with_value(CONVERSION_INFO_2_SLOT_NAME.clone(), conversion_slot2_word);

        let agglayer_storage_slots =
            vec![metadata_slot, bridge_slot, conversion_slot1, conversion_slot2];
        agglayer_faucet_component(agglayer_storage_slots)
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
}

// FAUCET REGISTRY HELPERS
// ================================================================================================

/// Creates a faucet registry map key from a faucet account ID.
///
/// The key format is `[0, 0, faucet_id_suffix, faucet_id_prefix]`.
pub fn faucet_registry_key(faucet_id: AccountId) -> Word {
    Word::new([Felt::ZERO, Felt::ZERO, faucet_id.suffix(), faucet_id.prefix().as_felt()])
}

// FAUCET CONVERSION STORAGE HELPERS
// ================================================================================================

/// Builds the two storage slot values for faucet conversion metadata.
///
/// The conversion metadata is stored in two value storage slots:
/// - Slot 1 (`miden::agglayer::faucet::conversion_info_1`): `[addr0, addr1, addr2, addr3]` — first
///   4 felts of the origin token address (5 × u32 limbs).
/// - Slot 2 (`miden::agglayer::faucet::conversion_info_2`): `[addr4, origin_network, scale, 0]` —
///   remaining address felt + origin network + scale factor.
///
/// # Parameters
/// - `origin_token_address`: The EVM token address in Ethereum format
/// - `origin_network`: The origin network/chain ID
/// - `scale`: The decimal scaling factor (exponent for 10^scale)
///
/// # Returns
/// A tuple of two `Word` values representing the two storage slot contents.
fn agglayer_faucet_conversion_slots(
    origin_token_address: &EthAddressFormat,
    origin_network: u32,
    scale: u8,
) -> (Word, Word) {
    let addr_elements = origin_token_address.to_elements();

    let slot1 = Word::new([addr_elements[0], addr_elements[1], addr_elements[2], addr_elements[3]]);

    let slot2 =
        Word::new([addr_elements[4], Felt::from(origin_network), Felt::from(scale), Felt::ZERO]);

    (slot1, slot2)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates an Agglayer Faucet component with the specified storage slots.
///
/// This component combines network faucet functionality with bridge validation
/// via Foreign Procedure Invocation (FPI). It provides a "claim" procedure that
/// validates CLAIM notes against a bridge MMR account before minting assets.
fn agglayer_faucet_component(storage_slots: Vec<StorageSlot>) -> AccountComponent {
    let library = agglayer_faucet_component_library();
    let metadata = AccountComponentMetadata::new("agglayer::faucet")
        .with_description("AggLayer faucet component with bridge validation")
        .with_supported_type(AccountType::FungibleFaucet);

    AccountComponent::new(library, storage_slots, metadata).expect(
        "agglayer_faucet component should satisfy the requirements of a valid account component",
    )
}
