use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, FieldElement, Word};

use super::{BasicFungibleFaucet, FungibleFaucetError};
use crate::account::auth::NoAuth;
use crate::account::components::regulated_network_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::procedure_digest;

// REGULATED NETWORK FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `distribute` procedure of the Regulated Network Fungible Faucet only
// once.
procedure_digest!(
    REGULATED_NETWORK_FUNGIBLE_FAUCET_DISTRIBUTE,
    RegulatedNetworkFungibleFaucet::DISTRIBUTE_PROC_NAME,
    regulated_network_fungible_faucet_library
);

// Initialize the digest of the `burn` procedure of the Regulated Network Fungible Faucet only once.
procedure_digest!(
    REGULATED_NETWORK_FUNGIBLE_FAUCET_BURN,
    RegulatedNetworkFungibleFaucet::BURN_PROC_NAME,
    regulated_network_fungible_faucet_library
);

static OWNER_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::ownable::owner_config")
        .expect("storage slot name should be valid")
});

static PAUSABLE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::pausable::paused")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] implementing a regulated network fungible faucet with pausable
/// functionality.
///
/// It reexports the procedures from `miden::contracts::faucets::regulated_network_fungible`. When
/// linking against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
/// - `pause`, which pauses the faucet, preventing minting and burning operations.
/// - `unpause`, which unpauses the faucet, allowing operations to resume.
///
/// Both `distribute` and `burn` can only be called from note scripts. `distribute` requires
/// authentication while `burn` does not require authentication and can be called by anyone.
/// `pause` and `unpause` can only be called by the owner. Both `distribute` and `burn` check
/// if the faucet is paused and will fail if it is.
/// Thus, this component must be combined with a component providing authentication.
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Fungible faucet metadata.
/// - [`Self::owner_config_slot`]: The owner account of this network faucet.
/// - [`Self::pausable_slot`]: The paused state of this network faucet (0 = unpaused, 1 = paused).
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct RegulatedNetworkFungibleFaucet {
    faucet: BasicFungibleFaucet,
    owner_account_id: AccountId,
}

impl RegulatedNetworkFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = 12;

    const DISTRIBUTE_PROC_NAME: &str = "regulated_network_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "regulated_network_fungible_faucet::burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`RegulatedNetworkFungibleFaucet`] component from the given pieces of
    /// metadata.
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply parameter exceeds maximum possible amount for a fungible asset
    ///   ([`miden_protocol::asset::FungibleAsset::MAX_AMOUNT`])
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        owner_account_id: AccountId,
    ) -> Result<Self, FungibleFaucetError> {
        // Create the basic fungible faucet (this validates the metadata)
        let faucet = BasicFungibleFaucet::new(symbol, decimals, max_supply)?;

        Ok(Self { faucet, owner_account_id })
    }

    /// Attempts to create a new [`RegulatedNetworkFungibleFaucet`] component from the associated
    /// account interface and storage.
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the provided [`AccountInterface`] does not contain a
    ///   [`AccountComponentInterface::RegulatedNetworkFungibleFaucet`] component.
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply value exceeds maximum possible amount for a fungible asset of
    ///   [`miden_protocol::asset::FungibleAsset::MAX_AMOUNT`].
    /// - the token symbol encoded value exceeds the maximum value of
    ///   [`TokenSymbol::MAX_ENCODED_VALUE`].
    fn try_from_interface(
        interface: AccountInterface,
        storage: &AccountStorage,
    ) -> Result<Self, FungibleFaucetError> {
        for component in interface.components().iter() {
            if let AccountComponentInterface::RegulatedNetworkFungibleFaucet = component {
                // obtain metadata from storage using offset provided by
                // RegulatedNetworkFungibleFaucet interface
                let faucet_metadata = storage
                    .get_item(RegulatedNetworkFungibleFaucet::metadata_slot())
                    .map_err(|err| FungibleFaucetError::StorageLookupFailed {
                        slot_name: RegulatedNetworkFungibleFaucet::metadata_slot().clone(),
                        source: err,
                    })?;
                let [max_supply, decimals, token_symbol, _] = *faucet_metadata;

                // obtain owner account ID from the next storage slot
                let owner_account_id_word: Word = storage
                    .get_item(RegulatedNetworkFungibleFaucet::owner_config_slot())
                    .map_err(|err| FungibleFaucetError::StorageLookupFailed {
                        slot_name: RegulatedNetworkFungibleFaucet::owner_config_slot().clone(),
                        source: err,
                    })?;

                // Convert Word back to AccountId
                // Storage format: [0, 0, suffix, prefix]
                let prefix = owner_account_id_word[3];
                let suffix = owner_account_id_word[2];
                let owner_account_id = AccountId::new_unchecked([prefix, suffix]);

                // verify metadata values and create BasicFungibleFaucet
                let token_symbol = TokenSymbol::try_from(token_symbol)
                    .map_err(FungibleFaucetError::InvalidTokenSymbol)?;
                let decimals = decimals.as_int().try_into().map_err(|_| {
                    FungibleFaucetError::TooManyDecimals {
                        actual: decimals.as_int(),
                        max: Self::MAX_DECIMALS,
                    }
                })?;

                let faucet = BasicFungibleFaucet::new(token_symbol, decimals, max_supply)?;

                return Ok(Self { faucet, owner_account_id });
            }
        }

        Err(FungibleFaucetError::NoAvailableInterface)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`RegulatedNetworkFungibleFaucet`]'s metadata is
    /// stored.
    pub fn metadata_slot() -> &'static StorageSlotName {
        &super::METADATA_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the [`RegulatedNetworkFungibleFaucet`]'s owner
    /// configuration is stored.
    pub fn owner_config_slot() -> &'static StorageSlotName {
        &OWNER_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the [`RegulatedNetworkFungibleFaucet`]'s paused state
    /// is stored.
    pub fn pausable_slot() -> &'static StorageSlotName {
        &PAUSABLE_SLOT_NAME
    }

    /// Returns the symbol of the faucet.
    pub fn symbol(&self) -> TokenSymbol {
        self.faucet.symbol()
    }

    /// Returns the decimals of the faucet.
    pub fn decimals(&self) -> u8 {
        self.faucet.decimals()
    }

    /// Returns the max supply of the faucet.
    pub fn max_supply(&self) -> Felt {
        self.faucet.max_supply()
    }

    /// Returns the owner account ID of the faucet.
    pub fn owner_account_id(&self) -> AccountId {
        self.owner_account_id
    }

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *REGULATED_NETWORK_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *REGULATED_NETWORK_FUNGIBLE_FAUCET_BURN
    }
}

impl From<RegulatedNetworkFungibleFaucet> for AccountComponent {
    fn from(regulated_faucet: RegulatedNetworkFungibleFaucet) -> Self {
        // Note: data is stored as [a0, a1, a2, a3] but loaded onto the stack as
        // [a3, a2, a1, a0, ...]
        let metadata = Word::new([
            regulated_faucet.faucet.max_supply(),
            Felt::from(regulated_faucet.faucet.decimals()),
            regulated_faucet.faucet.symbol().into(),
            Felt::ZERO,
        ]);

        // Convert AccountId into its Word encoding for storage.
        let owner_account_id_word: Word = [
            Felt::new(0),
            Felt::new(0),
            regulated_faucet.owner_account_id.suffix(),
            regulated_faucet.owner_account_id.prefix().as_felt(),
        ]
        .into();

        let metadata_slot = StorageSlot::with_value(
            RegulatedNetworkFungibleFaucet::metadata_slot().clone(),
            metadata,
        );
        let owner_slot = StorageSlot::with_value(
            RegulatedNetworkFungibleFaucet::owner_config_slot().clone(),
            owner_account_id_word,
        );
        // Initialize pausable slot to [0, 0, 0, 0] (unpaused state)
        let pausable_slot = StorageSlot::with_value(
            RegulatedNetworkFungibleFaucet::pausable_slot().clone(),
            Word::new([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        );

        AccountComponent::new(
            regulated_network_fungible_faucet_library(),
            vec![metadata_slot, owner_slot, pausable_slot]
        )
            .expect("regulated network fungible faucet component should satisfy the requirements of a valid account component")
            .with_supported_type(AccountType::FungibleFaucet)
    }
}

impl TryFrom<Account> for RegulatedNetworkFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(&account);

        RegulatedNetworkFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for RegulatedNetworkFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(account);

        RegulatedNetworkFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

/// Creates a new faucet account with regulated network fungible faucet interface and provided
/// metadata (token symbol, decimals, max supply, owner account ID).
///
/// The regulated network faucet interface exposes four procedures:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
/// - `pause`, which pauses the faucet, preventing minting and burning operations.
/// - `unpause`, which unpauses the faucet, allowing operations to resume.
///
/// Both `distribute` and `burn` can only be called from note scripts. `distribute` requires
/// authentication using the NoAuth scheme. `burn` does not require authentication and can be
/// called by anyone. `pause` and `unpause` can only be called by the owner. Both `distribute`
/// and `burn` check if the faucet is paused and will fail if it is.
///
/// Network fungible faucets always use:
/// - [`AccountStorageMode::Network`] for storage
/// - [`NoAuth`] for authentication
///
/// The storage layout of the regulated network faucet account is:
/// - Slot 0: Reserved slot for faucets.
/// - Slot 1: Public Key of the authentication component.
/// - Slot 2: [num_trigger_procs, allow_unauthorized_output_notes, allow_unauthorized_input_notes,
///   0].
/// - Slot 3: A map with trigger procedure roots.
/// - Slot 4: Token metadata of the faucet.
/// - Slot 5: Owner account ID.
/// - Slot 6: Paused state (0 = unpaused, 1 = paused).
pub fn create_regulated_network_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    owner_account_id: AccountId,
) -> Result<Account, FungibleFaucetError> {
    let auth_component: AccountComponent = NoAuth::new().into();

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_auth_component(auth_component)
        .with_component(RegulatedNetworkFungibleFaucet::new(
            symbol,
            decimals,
            max_supply,
            owner_account_id,
        )?)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}
