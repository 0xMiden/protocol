use alloc::vec::Vec;

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
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::{
    Description,
    ExternalLink,
    FungibleFaucetError,
    LogoURI,
    TokenMetadata,
    TokenMetadataError,
    TokenName,
};
use crate::account::access::AccessControl;
use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig, NoAuth};
use crate::account::components::fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::policies::TokenPolicyManager;
use crate::{AuthMethod, procedure_digest};

mod builder;
pub use builder::FungibleFaucetBuilder;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Storage slot holding the token config word `[token_supply, max_supply, decimals,
/// token_symbol]` for a [`FungibleFaucet`].
pub(crate) static TOKEN_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::fungible::token_config")
        .expect("storage slot name should be valid")
});

/// Schema type string for the token symbol field in the token config slot.
const TOKEN_SYMBOL_TYPE: &str = "miden::standards::faucets::fungible::token_symbol";

// FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `mint_and_send` procedure of the Fungible Faucet only once.
procedure_digest!(
    FUNGIBLE_FAUCET_MINT_AND_SEND,
    FungibleFaucet::NAME,
    FungibleFaucet::MINT_PROC_NAME,
    fungible_faucet_library
);

// Initialize the digest of the `receive_and_burn` procedure of the Fungible Faucet only once.
procedure_digest!(
    FUNGIBLE_FAUCET_RECEIVE_AND_BURN,
    FungibleFaucet::NAME,
    FungibleFaucet::RECEIVE_AND_BURN_PROC_NAME,
    fungible_faucet_library
);

/// An [`AccountComponent`] implementing a fungible faucet.
///
/// This component bundles the asset minting/burning procedures and the token metadata
/// (name, description, logo URI, external link) together. Whether the faucet behaves like a
/// "basic" public faucet or a network-style faucet is a function of the surrounding account
/// configuration (storage mode, auth component, access control component, and policy manager
/// configuration), not of the faucet component itself.
///
/// It re-exports the procedures from `miden::standards::faucets::fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler — which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `mint_and_send`, which mints an asset and creates a note for the provided recipient.
/// - `receive_and_burn`, which receives the fungible asset from the active note and burns it.
/// - The token metadata accessors and owner-gated setters (see the embedded [`TokenMetadata`]).
///
/// The `mint_and_send` procedure is gated by the active mint policy from the associated
/// [`TokenPolicyManager`]. `receive_and_burn` can only be called from a note script and is gated
/// by the active burn policy.
///
/// This component supports accounts of type [`AccountType::FungibleFaucet`].
///
/// [builder]: crate::code_builder::CodeBuilder
/// [`TokenPolicyManager`]: crate::account::policies::TokenPolicyManager
#[derive(Debug, Clone)]
pub struct FungibleFaucet {
    token_supply: Felt,
    max_supply: Felt,
    decimals: u8,
    symbol: TokenSymbol,
    /// Embeds name, optional fields, and mutability flags.
    metadata: TokenMetadata,
}

impl FungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::fungible_faucet";

    /// The maximum number of decimals supported.
    pub const MAX_DECIMALS: u8 = 12;

    const MINT_PROC_NAME: &'static str = "mint_and_send";
    const RECEIVE_AND_BURN_PROC_NAME: &'static str = "receive_and_burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a builder for [`FungibleFaucet`] with the required fields set.
    ///
    /// This is the main entry point for constructing a faucet; optional fields and the initial
    /// token supply can be set via the builder before calling
    /// [`FungibleFaucetBuilder::build`].
    ///
    /// # Parameters
    ///
    /// - `name`: display name (at most 32 UTF-8 bytes).
    /// - `symbol`: token symbol.
    /// - `decimals`: decimal precision (0–12).
    /// - `max_supply`: maximum token supply, as a validated [`AssetAmount`].
    pub fn builder(
        name: TokenName,
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: AssetAmount,
    ) -> FungibleFaucetBuilder {
        FungibleFaucetBuilder::new(name, symbol, decimals, max_supply)
    }

    /// Validates all fields and constructs a [`FungibleFaucet`].
    ///
    /// This is the single point where `Self { ... }` is constructed. All other constructors
    /// delegate here.
    pub(crate) fn new_validated(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: AssetAmount,
        token_supply: AssetAmount,
        metadata: TokenMetadata,
    ) -> Result<Self, FungibleFaucetError> {
        if decimals > Self::MAX_DECIMALS {
            return Err(FungibleFaucetError::TooManyDecimals {
                actual: decimals as u64,
                max: Self::MAX_DECIMALS,
            });
        }

        if u64::from(token_supply) > u64::from(max_supply) {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply: u64::from(token_supply),
                max_supply: u64::from(max_supply),
            });
        }

        Ok(Self {
            token_supply: token_supply.into(),
            max_supply: max_supply.into(),
            decimals,
            symbol,
            metadata,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the digest of the `mint_and_send` account procedure.
    pub fn mint_and_send_digest() -> Word {
        *FUNGIBLE_FAUCET_MINT_AND_SEND
    }

    /// Returns the digest of the `receive_and_burn` account procedure.
    pub fn receive_and_burn_digest() -> Word {
        *FUNGIBLE_FAUCET_RECEIVE_AND_BURN
    }

    /// Returns the [`StorageSlotName`] holding the token config word
    /// `[token_supply, max_supply, decimals, token_symbol]`.
    pub fn token_config_slot() -> &'static StorageSlotName {
        &TOKEN_CONFIG_SLOT
    }

    /// Returns the current token supply (amount issued).
    pub fn token_supply(&self) -> Felt {
        self.token_supply
    }

    /// Returns the maximum token supply.
    pub fn max_supply(&self) -> Felt {
        self.max_supply
    }

    /// Returns the number of decimals.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns the token symbol.
    pub fn symbol(&self) -> &TokenSymbol {
        &self.symbol
    }

    /// Returns the token name.
    pub fn name(&self) -> &TokenName {
        self.metadata.name()
    }

    /// Returns the optional description.
    pub fn description(&self) -> Option<&Description> {
        self.metadata.description()
    }

    /// Returns the optional logo URI.
    pub fn logo_uri(&self) -> Option<&LogoURI> {
        self.metadata.logo_uri()
    }

    /// Returns the optional external link.
    pub fn external_link(&self) -> Option<&ExternalLink> {
        self.metadata.external_link()
    }

    /// Returns the storage slot schema for the token config slot.
    pub fn token_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        let token_symbol_type = SchemaType::new(TOKEN_SYMBOL_TYPE).expect("valid type");
        (
            Self::token_config_slot().clone(),
            StorageSlotSchema::value(
                "Token config",
                [
                    FeltSchema::felt("token_supply").with_default(Felt::ZERO),
                    FeltSchema::felt("max_supply"),
                    FeltSchema::u8("decimals"),
                    FeltSchema::new_typed(token_symbol_type, "symbol"),
                ],
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let mut schema_entries = vec![Self::token_config_slot_schema()];
        schema_entries.extend(TokenMetadata::storage_schema());

        let storage_schema =
            StorageSchema::new(schema_entries).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description(
                "Fungible faucet component bundling minting, burning, and token metadata",
            )
            .with_storage_schema(storage_schema)
    }

    /// Returns the storage slots produced by this faucet (token config word + name + mutability
    /// config + description + logo URI + external link).
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();
        slots.push(self.token_config_slot_value());
        slots.extend(self.metadata.into_storage_slots());
        slots
    }

    /// Returns the single storage slot for the token config word.
    fn token_config_slot_value(&self) -> StorageSlot {
        let word = Word::new([
            self.token_supply,
            self.max_supply,
            Felt::from(self.decimals),
            self.symbol.clone().into(),
        ]);
        StorageSlot::with_value(Self::token_config_slot().clone(), word)
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the token_supply (in base units).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the token supply exceeds the max supply.
    pub fn with_token_supply(mut self, token_supply: Felt) -> Result<Self, FungibleFaucetError> {
        if token_supply.as_canonical_u64() > self.max_supply.as_canonical_u64() {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply: token_supply.as_canonical_u64(),
                max_supply: self.max_supply.as_canonical_u64(),
            });
        }

        self.token_supply = token_supply;

        Ok(self)
    }

    /// Sets whether the description can be updated by the owner.
    pub fn with_description_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_description_mutable(mutable);
        self
    }

    /// Sets whether the logo URI can be updated by the owner.
    pub fn with_logo_uri_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_logo_uri_mutable(mutable);
        self
    }

    /// Sets whether the external link can be updated by the owner.
    pub fn with_external_link_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_external_link_mutable(mutable);
        self
    }

    /// Sets whether the max supply can be updated by the owner.
    pub fn with_max_supply_mutable(mut self, mutable: bool) -> Self {
        self.metadata = self.metadata.with_max_supply_mutable(mutable);
        self
    }

    // INTERFACE EXTRACTION
    // --------------------------------------------------------------------------------------------

    /// Checks that the account contains the fungible faucet interface.
    fn try_from_interface(
        interface: AccountInterface,
        storage: &AccountStorage,
    ) -> Result<Self, FungibleFaucetError> {
        if !interface.components().contains(&AccountComponentInterface::FungibleFaucet) {
            return Err(FungibleFaucetError::MissingFungibleFaucetInterface);
        }

        FungibleFaucet::try_from(storage)
    }

    /// Reconstructs from the token config word and the embedded [`TokenMetadata`] read from
    /// storage.
    pub(crate) fn from_token_config_word_and_token_metadata(
        word: Word,
        metadata: TokenMetadata,
    ) -> Result<Self, FungibleFaucetError> {
        let [token_supply, max_supply, decimals_felt, token_symbol] = *word;
        let symbol =
            TokenSymbol::try_from(token_symbol).map_err(TokenMetadataError::InvalidTokenSymbol)?;
        let decimals: u8 = decimals_felt.as_canonical_u64().try_into().map_err(|_| {
            FungibleFaucetError::TooManyDecimals {
                actual: decimals_felt.as_canonical_u64(),
                max: Self::MAX_DECIMALS,
            }
        })?;
        let max_supply_raw = max_supply.as_canonical_u64();
        let max_supply = AssetAmount::new(max_supply_raw).map_err(|_| {
            FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply_raw,
                max: AssetAmount::MAX,
            }
        })?;
        let token_supply_raw = token_supply.as_canonical_u64();
        let token_supply = AssetAmount::new(token_supply_raw).map_err(|_| {
            FungibleFaucetError::MaxSupplyTooLarge {
                actual: token_supply_raw,
                max: AssetAmount::MAX,
            }
        })?;

        Self::new_validated(symbol, decimals, max_supply, token_supply, metadata)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<FungibleFaucet> for AccountComponent {
    fn from(faucet: FungibleFaucet) -> Self {
        let component_metadata = FungibleFaucet::component_metadata();
        let storage_slots = faucet.into_storage_slots();

        AccountComponent::new(fungible_faucet_library(), storage_slots, component_metadata)
            .expect("fungible faucet component should satisfy the requirements of a valid account component")
    }
}

impl TryFrom<&AccountStorage> for FungibleFaucet {
    type Error = FungibleFaucetError;

    /// Reconstructs [`FungibleFaucet`] by reading all relevant storage slots: the token
    /// config word, name, mutability config, description, logo URI, and external link.
    fn try_from(storage: &AccountStorage) -> Result<Self, Self::Error> {
        let token_config_word = storage.get_item(Self::token_config_slot()).map_err(|err| {
            TokenMetadataError::StorageLookupFailed {
                slot_name: Self::token_config_slot().clone(),
                source: err,
            }
        })?;

        let token_metadata = TokenMetadata::try_from_storage(storage)?;

        Self::from_token_config_word_and_token_metadata(token_config_word, token_metadata)
    }
}

impl TryFrom<Account> for FungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(&account);

        FungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for FungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(account);

        FungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

// FACTORY
// ================================================================================================

/// Creates a new fungible faucet account by composing the required components.
///
/// The behaviour of the resulting faucet (basic vs network-style) is determined entirely by the
/// combination of arguments passed in:
/// - `storage_mode`: typically [`AccountStorageMode::Public`] for basic faucets, or
///   [`AccountStorageMode::Network`] for network-style faucets.
/// - `auth_method`: typically [`AuthMethod::SingleSig`] for basic faucets, or
///   [`AuthMethod::NoAuth`] for network-style faucets.
/// - `access_control`: [`AccessControl::AuthControlled`] for auth-only faucets, or
///   [`AccessControl::Ownable2Step`] / [`AccessControl::Rbac`] for owner-controlled faucets.
/// - `token_policy_manager`: the unified [`TokenPolicyManager`] holding both mint and burn policy
///   plus the shared [`PolicyAuthority`].
///
/// The faucet itself, including all token metadata, is provided in the `faucet` parameter (see
/// [`FungibleFaucet::builder`]).
///
/// [`PolicyAuthority`]: crate::account::policies::PolicyAuthority
pub fn create_fungible_faucet(
    init_seed: [u8; 32],
    faucet: FungibleFaucet,
    storage_mode: AccountStorageMode,
    auth_method: AuthMethod,
    access_control: AccessControl,
    token_policy_manager: TokenPolicyManager,
) -> Result<Account, FungibleFaucetError> {
    let mint_proc_root = FungibleFaucet::mint_and_send_digest();

    let auth_component: AccountComponent = match auth_method {
        AuthMethod::SingleSig { approver: (pub_key, auth_scheme) } => AuthSingleSigAcl::new(
            pub_key,
            auth_scheme,
            AuthSingleSigAclConfig::new()
                .with_auth_trigger_procedures(vec![mint_proc_root])
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into(),
        AuthMethod::NoAuth => NoAuth::new().into(),
        AuthMethod::Unknown => {
            return Err(FungibleFaucetError::UnsupportedAuthMethod(
                "fungible faucets cannot be created with Unknown authentication method".into(),
            ));
        },
        AuthMethod::Multisig { .. } => {
            return Err(FungibleFaucetError::UnsupportedAuthMethod(
                "fungible faucets do not support Multisig authentication".into(),
            ));
        },
    };

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(storage_mode)
        .with_auth_component(auth_component)
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}
