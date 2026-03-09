use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
use miden_protocol::{Felt, Word};

<<<<<<< HEAD
use super::{
    Description,
    ExternalLink,
    FungibleFaucetError,
    FungibleTokenMetadata,
    LogoURI,
    TokenName,
};
=======
use super::{FungibleFaucetError, TokenMetadata};
use crate::account::access::Ownable2Step;
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))
use crate::account::auth::NoAuth;
use crate::account::components::network_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::procedure_digest;

/// The schema type for token symbols.
const TOKEN_SYMBOL_TYPE: &str = "miden::standards::fungible_faucets::metadata::token_symbol";
<<<<<<< HEAD
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::metadata::TokenMetadata as TokenMetadataInfo;
use crate::procedure_digest;
=======
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))

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
/// Ownership is managed via a two-step transfer pattern ([`Ownable2Step`]). The current owner
/// must first nominate a new owner, who then accepts the transfer.
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Fungible faucet metadata.
/// - [`Ownable2Step::slot_name`]: The owner and nominated owner of this network faucet.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct NetworkFungibleFaucet {
<<<<<<< HEAD
    metadata: FungibleTokenMetadata,
    owner_account_id: AccountId,
    info: Option<TokenMetadataInfo>,
=======
    metadata: TokenMetadata,
    ownership: Ownable2Step,
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))
}

impl NetworkFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::network_fungible_faucet";

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = FungibleTokenMetadata::MAX_DECIMALS;

    const DISTRIBUTE_PROC_NAME: &str = "network_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "network_fungible_faucet::burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`NetworkFungibleFaucet`] component from the given pieces of metadata.
    ///
    /// Optional `description`, `logo_uri`, and `external_link` are stored in the component's
    /// storage slots when building an account.
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
        name: TokenName,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        external_link: Option<ExternalLink>,
    ) -> Result<Self, FungibleFaucetError> {
<<<<<<< HEAD
        let metadata = FungibleTokenMetadata::new(
            symbol,
            decimals,
            max_supply,
            name,
            description,
            logo_uri,
            external_link,
        )?;
        Ok(Self { metadata, owner_account_id, info: None })
=======
        let metadata = TokenMetadata::new(symbol, decimals, max_supply)?;
        let ownership = Ownable2Step::new(owner_account_id);
        Ok(Self { metadata, ownership })
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))
    }

    /// Creates a new [`NetworkFungibleFaucet`] component from the given [`FungibleTokenMetadata`].
    ///
    /// This is a convenience constructor that allows creating a faucet from pre-validated
    /// metadata.
<<<<<<< HEAD
    pub fn from_metadata(metadata: FungibleTokenMetadata, owner_account_id: AccountId) -> Self {
        Self { metadata, owner_account_id, info: None }
    }

    /// Attaches token metadata (name, description, logo, link, mutability flags) to the
    /// faucet. These storage slots will be included in the component when built.
    pub fn with_info(mut self, info: TokenMetadataInfo) -> Self {
        self.info = Some(info);
        self
=======
    pub fn from_metadata(metadata: TokenMetadata, owner_account_id: AccountId) -> Self {
        let ownership = Ownable2Step::new(owner_account_id);
        Self { metadata, ownership }
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))
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
    /// - the token supply exceeds the max supply.
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

        // Read token metadata from storage
        let metadata = FungibleTokenMetadata::try_from(storage)?;

        // Read ownership data from storage
        let ownership =
            Ownable2Step::try_from_storage(storage).map_err(FungibleFaucetError::OwnershipError)?;

<<<<<<< HEAD
        // Convert Word back to AccountId
        // Storage format: [0, 0, suffix, prefix]
        let prefix = owner_account_id_word[3];
        let suffix = owner_account_id_word[2];
        let owner_account_id = AccountId::new_unchecked([prefix, suffix]);

        Ok(Self { metadata, owner_account_id, info: None })
=======
        Ok(Self { metadata, ownership })
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`NetworkFungibleFaucet`]'s metadata is stored
    /// (slot 0).
    pub fn metadata_slot() -> &'static StorageSlotName {
        FungibleTokenMetadata::metadata_slot()
    }

<<<<<<< HEAD
    /// Returns the [`StorageSlotName`] where the [`NetworkFungibleFaucet`]'s owner configuration is
    /// stored (slot 1).
    pub fn owner_config_slot() -> &'static StorageSlotName {
        crate::account::metadata::owner_config_slot()
    }

=======
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))
    /// Returns the storage slot schema for the metadata slot.
    pub fn metadata_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        let token_symbol_type = SchemaType::new(TOKEN_SYMBOL_TYPE).expect("valid type");
        (
            Self::metadata_slot().clone(),
            StorageSlotSchema::value(
                "Token metadata",
                [
                    FeltSchema::felt("token_supply").with_default(Felt::new(0)),
                    FeltSchema::felt("max_supply"),
                    FeltSchema::u8("decimals"),
                    FeltSchema::new_typed(token_symbol_type, "symbol"),
                ],
            ),
        )
    }

    /// Returns the token metadata.
    pub fn metadata(&self) -> &FungibleTokenMetadata {
        &self.metadata
    }

    /// Returns the symbol of the faucet.
    pub fn symbol(&self) -> TokenSymbol {
        self.metadata.symbol()
    }

    /// Returns the decimals of the faucet.
    pub fn decimals(&self) -> u8 {
        self.metadata.decimals()
    }

    /// Returns the max supply (in base units) of the faucet.
    ///
    /// This is the highest amount of tokens that can be minted from this faucet.
    pub fn max_supply(&self) -> Felt {
        self.metadata.max_supply()
    }

    /// Returns the token supply (in base units) of the faucet.
    ///
    /// This is the amount of tokens that were minted from the faucet so far. Its value can never
    /// exceed [`Self::max_supply`].
    pub fn token_supply(&self) -> Felt {
        self.metadata.token_supply()
    }

    /// Returns the owner account ID of the faucet, or `None` if ownership has been renounced.
    pub fn owner_account_id(&self) -> Option<AccountId> {
        self.ownership.owner()
    }

    /// Returns the nominated owner account ID, or `None` if no transfer is in progress.
    pub fn nominated_owner(&self) -> Option<AccountId> {
        self.ownership.nominated_owner()
    }

    /// Returns the ownership data of the faucet.
    pub fn ownership(&self) -> &Ownable2Step {
        &self.ownership
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

    /// Sets the token_supply (in base units) of the network fungible faucet.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the token supply exceeds the max supply.
    pub fn with_token_supply(mut self, token_supply: Felt) -> Result<Self, FungibleFaucetError> {
        self.metadata = self.metadata.with_token_supply(token_supply)?;
        Ok(self)
    }
}

impl From<NetworkFungibleFaucet> for AccountComponent {
    fn from(network_faucet: NetworkFungibleFaucet) -> Self {
        let metadata_slot = network_faucet.metadata.into();
<<<<<<< HEAD

        let owner_account_id_word: Word = [
            Felt::new(0),
            Felt::new(0),
            network_faucet.owner_account_id.suffix(),
            network_faucet.owner_account_id.prefix().as_felt(),
        ]
        .into();

        let owner_slot = StorageSlot::with_value(
            NetworkFungibleFaucet::owner_config_slot().clone(),
            owner_account_id_word,
        );
=======
        let owner_slot = network_faucet.ownership.to_storage_slot();
>>>>>>> 698fa6fb (feat: implement `Ownable2Step` (#2292))

        let mut slots = vec![metadata_slot, owner_slot];
        if let Some(info) = &network_faucet.info {
            slots.extend(info.storage_slots());
        }

        let storage_schema = StorageSchema::new([
            NetworkFungibleFaucet::metadata_slot_schema(),
            Ownable2Step::slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(
            NetworkFungibleFaucet::NAME,
            [AccountType::FungibleFaucet],
        )
        .with_description("Network fungible faucet component for minting and burning tokens")
        .with_storage_schema(storage_schema);

        AccountComponent::new(network_fungible_faucet_library(), slots, metadata)
            .expect("network fungible faucet component should satisfy the requirements of a valid account component")
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

/// Creates a new faucet account with network fungible faucet interface and provided metadata.
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
    metadata: FungibleTokenMetadata,
    owner: AccountId,
) -> Result<Account, FungibleFaucetError> {
    let auth_component: AccountComponent = NoAuth::new().into();

    let mut info = TokenMetadataInfo::new().with_name(metadata.name().clone());
    if let Some(d) = metadata.description() {
        info = info.with_description(d.clone(), false);
    }
    if let Some(l) = metadata.logo_uri() {
        info = info.with_logo_uri(l.clone(), false);
    }
    if let Some(e) = metadata.external_link() {
        info = info.with_external_link(e.clone(), false);
    }

    let faucet = NetworkFungibleFaucet::from_metadata(metadata, owner).with_info(info);

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_auth_component(auth_component)
        .with_component(faucet)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}
