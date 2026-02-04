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
use miden_protocol::{Felt, Word};

use super::{BasicFungibleFaucet, FungibleFaucetError};
use crate::account::auth::NoAuth;
use crate::account::components::network_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::procedure_digest;

// NETWORK FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `distribute` procedure of the Network Fungible Faucet only once.
procedure_digest!(
    NETWORK_FUNGIBLE_FAUCET_DISTRIBUTE,
    NetworkFungibleFaucet::DISTRIBUTE_PROC_NAME,
    network_fungible_faucet_library
);

// Initialize the digest of the `burn` procedure of the Network Fungible Faucet only once.
procedure_digest!(
    NETWORK_FUNGIBLE_FAUCET_BURN,
    NetworkFungibleFaucet::BURN_PROC_NAME,
    network_fungible_faucet_library
);

static OWNER_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::access::ownable::owner_config")
        .expect("storage slot name should be valid")
});

/// An [`AccountComponent`] implementing a network fungible faucet.
///
/// It reexports the procedures from `miden::standards::faucets::network_fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `distribute` and `burn` can only be called from note scripts. `distribute` requires
/// authentication while `burn` does not require authentication and can be called by anyone.
/// Thus, this component must be combined with a component providing authentication.
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Fungible faucet metadata.
/// - [`Self::owner_config_slot`]: The owner account of this network faucet.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct NetworkFungibleFaucet {
    faucet: BasicFungibleFaucet,
    owner_account_id: AccountId,
}

impl NetworkFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = 12;

    const DISTRIBUTE_PROC_NAME: &str = "network_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "network_fungible_faucet::burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NetworkFungibleFaucet`] component from the given pieces of metadata.
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

    /// Attempts to create a new [`NetworkFungibleFaucet`] component from the associated account
    /// interface and storage.
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the provided [`AccountInterface`] does not contain a
    ///   [`AccountComponentInterface::NetworkFungibleFaucet`] component.
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply value exceeds maximum possible amount for a fungible asset of
    ///   [`miden_protocol::asset::FungibleAsset::MAX_AMOUNT`].
    /// - the token symbol encoded value exceeds the maximum value of
    ///   [`TokenSymbol::MAX_ENCODED_VALUE`].
    fn try_from_interface(
        interface: AccountInterface,
        storage: &AccountStorage,
    ) -> Result<Self, FungibleFaucetError> {
        // Check that the procedures of the network fungible faucet exist in the account.
        if !interface
            .components()
            .contains(&AccountComponentInterface::NetworkFungibleFaucet)
        {
            return Err(FungibleFaucetError::MissingNetworkFungibleFaucetInterface);
        }

        debug_assert_eq!(
            NetworkFungibleFaucet::metadata_slot(),
            BasicFungibleFaucet::metadata_slot(),
            "the code below assumes the slots of both components are identical"
        );

        // This is safe because the NetworkFungibleFaucet's metadata slot is identical to the one in
        // the basic fungible faucet.
        let faucet = BasicFungibleFaucet::try_from_storage(storage)?;

        // obtain owner account ID from the next storage slot
        let owner_account_id_word: Word = storage
            .get_item(NetworkFungibleFaucet::owner_config_slot())
            .map_err(|err| FungibleFaucetError::StorageLookupFailed {
                slot_name: NetworkFungibleFaucet::owner_config_slot().clone(),
                source: err,
            })?;

        // Convert Word back to AccountId
        // Storage format: [0, 0, suffix, prefix]
        let prefix = owner_account_id_word[3];
        let suffix = owner_account_id_word[2];
        let owner_account_id = AccountId::new_unchecked([prefix, suffix]);

        Ok(Self { faucet, owner_account_id })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`NetworkFungibleFaucet`]'s metadata is stored.
    pub fn metadata_slot() -> &'static StorageSlotName {
        &super::METADATA_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the [`NetworkFungibleFaucet`]'s owner configuration is
    /// stored.
    pub fn owner_config_slot() -> &'static StorageSlotName {
        &OWNER_CONFIG_SLOT_NAME
    }

    /// Returns the symbol of the faucet.
    pub fn symbol(&self) -> TokenSymbol {
        self.faucet.symbol()
    }

    /// Returns the decimals of the faucet.
    pub fn decimals(&self) -> u8 {
        self.faucet.decimals()
    }

    /// Returns the max supply (in base units) of the faucet.
    ///
    /// This is the highest amount of tokens that can be minted from this faucet.
    pub fn max_supply(&self) -> Felt {
        self.faucet.max_supply()
    }

    /// Returns the token supply (in base units) of the faucet.
    ///
    /// This is the amount of tokens that were minted from the faucet so far. Its value can never
    /// exceed [`Self::max_supply`].
    pub fn token_supply(&self) -> Felt {
        self.faucet.token_supply()
    }

    /// Returns the owner account ID of the faucet.
    pub fn owner_account_id(&self) -> AccountId {
        self.owner_account_id
    }

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *NETWORK_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *NETWORK_FUNGIBLE_FAUCET_BURN
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the token_supply (in base units) of the basic fungible faucet.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the token supply exceeds the max supply.
    pub fn with_token_supply(mut self, token_supply: Felt) -> Result<Self, FungibleFaucetError> {
        self.faucet = self.faucet.with_token_supply(token_supply)?;

        Ok(self)
    }
}

impl From<NetworkFungibleFaucet> for AccountComponent {
    fn from(network_faucet: NetworkFungibleFaucet) -> Self {
        let metadata_word = network_faucet.faucet.to_metadata_word();

        // Convert AccountId into its Word encoding for storage.
        let owner_account_id_word: Word = [
            Felt::new(0),
            Felt::new(0),
            network_faucet.owner_account_id.suffix(),
            network_faucet.owner_account_id.prefix().as_felt(),
        ]
        .into();

        let metadata_slot =
            StorageSlot::with_value(NetworkFungibleFaucet::metadata_slot().clone(), metadata_word);
        let owner_slot = StorageSlot::with_value(
            NetworkFungibleFaucet::owner_config_slot().clone(),
            owner_account_id_word,
        );

        AccountComponent::new(
            network_fungible_faucet_library(),
            vec![metadata_slot, owner_slot]
        )
            .expect("network fungible faucet component should satisfy the requirements of a valid account component")
            .with_supported_type(AccountType::FungibleFaucet)
    }
}

impl TryFrom<Account> for NetworkFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(&account);

        NetworkFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for NetworkFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(account);

        NetworkFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

/// Creates a new faucet account with network fungible faucet interface and provided metadata
/// (token symbol, decimals, max supply, owner account ID).
///
/// The network faucet interface exposes two procedures:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `distribute` and `burn` can only be called from note scripts. `distribute` requires
/// authentication using the NoAuth scheme. `burn` does not require authentication and can be
/// called by anyone.
///
/// Network fungible faucets always use:
/// - [`AccountStorageMode::Network`] for storage
/// - [`NoAuth`] for authentication
///
/// The storage layout of the faucet account is documented on the [`NetworkFungibleFaucet`] type and
/// contains no additional storage slots for its auth ([`NoAuth`]).
pub fn create_network_fungible_faucet(
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
        .with_component(NetworkFungibleFaucet::new(symbol, decimals, max_supply, owner_account_id)?)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}
