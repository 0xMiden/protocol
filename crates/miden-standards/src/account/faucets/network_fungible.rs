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
    AccountStorage,
    AccountStorageMode,
    AccountType,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
use miden_protocol::{Felt, Word};

use super::{FungibleFaucetError, TokenMetadata};
use crate::account::access::AccessControl;
use crate::account::auth::NoAuth;
use crate::account::components::network_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::mint_policies::OwnerControlled;
use crate::procedure_digest;

/// The schema type for token symbols.
const TOKEN_SYMBOL_TYPE: &str = "miden::standards::fungible_faucets::metadata::token_symbol";

// NETWORK FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `mint_and_send` procedure of the Network Fungible Faucet only once.
procedure_digest!(
    NETWORK_FUNGIBLE_FAUCET_MINT_AND_SEND,
    NetworkFungibleFaucet::NAME,
    NetworkFungibleFaucet::MINT_PROC_NAME,
    network_fungible_faucet_library
);

// Initialize the digest of the `burn` procedure of the Network Fungible Faucet only once.
procedure_digest!(
    NETWORK_FUNGIBLE_FAUCET_BURN,
    NetworkFungibleFaucet::NAME,
    NetworkFungibleFaucet::BURN_PROC_NAME,
    network_fungible_faucet_library
);

/// An [`AccountComponent`] implementing a network fungible faucet.
///
/// It reexports the procedures from `miden::standards::faucets::network_fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `mint_and_send`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `mint_and_send` and `burn` can only be called from note scripts. `mint_and_send` requires
/// authentication while `burn` does not require authentication and can be called by anyone.
/// Thus, this component must be combined with a component providing authentication.
///
/// This component relies on [`crate::account::access::Ownable2Step`] for ownership checks in
/// `mint_and_send`. When building an account with this component,
/// [`crate::account::access::Ownable2Step`] must also be included.
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Fungible faucet metadata.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct NetworkFungibleFaucet {
    metadata: TokenMetadata,
}

impl NetworkFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::network_fungible_faucet";

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = TokenMetadata::MAX_DECIMALS;

    const MINT_PROC_NAME: &str = "mint_and_send";
    const BURN_PROC_NAME: &str = "burn";

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
    ) -> Result<Self, FungibleFaucetError> {
        let metadata = TokenMetadata::new(symbol, decimals, max_supply)?;
        Ok(Self { metadata })
    }

    /// Creates a new [`NetworkFungibleFaucet`] component from the given [`TokenMetadata`].
    ///
    /// This is a convenience constructor that allows creating a faucet from pre-validated
    /// metadata.
    pub fn from_metadata(metadata: TokenMetadata) -> Self {
        Self { metadata }
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
        let metadata = TokenMetadata::try_from(storage)?;

        Ok(Self { metadata })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`NetworkFungibleFaucet`]'s metadata is stored.
    pub fn metadata_slot() -> &'static StorageSlotName {
        TokenMetadata::metadata_slot()
    }

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
    pub fn metadata(&self) -> &TokenMetadata {
        &self.metadata
    }

    /// Returns the symbol of the faucet.
    pub fn symbol(&self) -> &TokenSymbol {
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

    /// Returns the digest of the `mint_and_send` account procedure.
    pub fn mint_and_send_digest() -> Word {
        *NETWORK_FUNGIBLE_FAUCET_MINT_AND_SEND
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

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([Self::metadata_slot_schema()])
            .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description("Network fungible faucet component for minting and burning tokens")
            .with_storage_schema(storage_schema)
    }
}

impl From<NetworkFungibleFaucet> for AccountComponent {
    fn from(network_faucet: NetworkFungibleFaucet) -> Self {
        let metadata_slot = network_faucet.metadata.into();
        let metadata = NetworkFungibleFaucet::component_metadata();

        AccountComponent::new(
            network_fungible_faucet_library(),
            vec![metadata_slot],
            metadata,
        )
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

/// Creates a new faucet account with network fungible faucet interface and provided metadata
/// (token symbol, decimals, max supply) and access control.
///
/// The network faucet interface exposes two procedures:
/// - `mint_and_send`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `mint_and_send` and `burn` can only be called from note scripts. `mint_and_send` requires
/// authentication using the NoAuth scheme. `burn` does not require authentication and can be
/// called by anyone.
///
/// Network fungible faucets always use:
/// - [`AccountStorageMode::Network`] for storage
/// - [`NoAuth`] for authentication
///
/// The storage layout of the faucet account is documented on the [`NetworkFungibleFaucet`] and
/// [`OwnerControlled`] and [`crate::account::access::Ownable2Step`] component types and
/// contains no additional storage slots for its auth ([`NoAuth`]).
pub fn create_network_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    access_control: AccessControl,
) -> Result<Account, FungibleFaucetError> {
    // Validate that access_control is Ownable2Step, as this faucet depends on it.
    // When new variants are added to AccessControl, update this match to either support
    // them or return Err(FungibleFaucetError::UnsupportedAccessControl).
    match access_control {
        AccessControl::Ownable2Step { .. } => {},
        #[allow(unreachable_patterns)]
        _ => {
            return Err(FungibleFaucetError::UnsupportedAccessControl(
                "network fungible faucets require Ownable2Step access control".into(),
            ));
        },
    }

    let auth_component: AccountComponent = NoAuth::new().into();

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_auth_component(auth_component)
        .with_component(NetworkFungibleFaucet::new(symbol, decimals, max_supply)?)
        .with_component(access_control)
        .with_component(OwnerControlled::owner_only())
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};

    use super::*;
    use crate::account::access::Ownable2Step;

    #[test]
    fn test_create_network_fungible_faucet() {
        let init_seed = [7u8; 32];
        let symbol = TokenSymbol::new("NET").expect("token symbol should be valid");
        let decimals = 8u8;
        let max_supply = Felt::new(1_000);

        let owner = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );

        let account = create_network_fungible_faucet(
            init_seed,
            symbol.clone(),
            decimals,
            max_supply,
            AccessControl::Ownable2Step { owner },
        )
        .expect("network faucet creation should succeed");

        let expected_owner_word = Ownable2Step::new(owner).to_word();
        assert_eq!(
            account.storage().get_item(Ownable2Step::slot_name()).unwrap(),
            expected_owner_word
        );

        let faucet = NetworkFungibleFaucet::try_from(&account)
            .expect("network fungible faucet should be extractable from account");
        assert_eq!(faucet.symbol(), &symbol);
        assert_eq!(faucet.decimals(), decimals);
        assert_eq!(faucet.max_supply(), max_supply);
        assert_eq!(faucet.token_supply(), Felt::ZERO);
    }
}
