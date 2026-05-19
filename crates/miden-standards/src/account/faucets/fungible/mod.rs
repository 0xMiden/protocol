use alloc::vec::Vec;

use miden_protocol::account::component::{
    AccountComponentCode,
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
    AccountProcedureRoot,
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
use crate::account::account_component_code;
use crate::account::auth::{AuthNetworkAccount, AuthSingleSigAcl, AuthSingleSigAclConfig, NoAuth};
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::policies::TokenPolicyManager;
use crate::{AuthMethod, procedure_root};

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

account_component_code!(FUNGIBLE_FAUCET_CODE, "faucets/fungible_faucet.masl");

// Initialize the procedure root of the `mint_and_send` procedure of the Fungible Faucet only once.
procedure_root!(
    FUNGIBLE_FAUCET_MINT_AND_SEND,
    FungibleFaucet::NAME,
    FungibleFaucet::MINT_PROC_NAME,
    FungibleFaucet::code()
);

// Initialize the procedure root of the `receive_and_burn` procedure of the Fungible Faucet only
// once.
procedure_root!(
    FUNGIBLE_FAUCET_RECEIVE_AND_BURN,
    FungibleFaucet::NAME,
    FungibleFaucet::RECEIVE_AND_BURN_PROC_NAME,
    FungibleFaucet::code()
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
    token_supply: AssetAmount,
    max_supply: AssetAmount,
    decimals: u8,
    symbol: TokenSymbol,
    /// Embeds name, optional fields, and mutability flags.
    metadata: TokenMetadata,
}

#[bon::bon]
impl FungibleFaucet {
    /// Returns a builder for [`FungibleFaucet`].
    ///
    /// Required setters: [`name`], [`symbol`], [`decimals`], [`max_supply`].
    /// Optional fields default to `None` (string fields) or `false` (mutability flags); the initial
    /// token supply defaults to zero.
    ///
    /// # Example
    ///
    /// ```
    /// # use miden_protocol::asset::{AssetAmount, TokenSymbol};
    /// # use miden_standards::account::faucets::FungibleFaucet;
    /// # use miden_standards::account::faucets::{Description, LogoURI, TokenName};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let faucet = FungibleFaucet::builder()
    ///     .name(TokenName::new("My Token")?)
    ///     .symbol(TokenSymbol::new("MTK")?)
    ///     .decimals(8)
    ///     .max_supply(AssetAmount::from(1_000_000u32))
    ///     .token_supply(AssetAmount::from(100u32))
    ///     .description(Description::new("A test token")?)
    ///     .logo_uri(LogoURI::new("https://example.com/logo.png")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`name`]: FungibleFaucetBuilder::name
    /// [`symbol`]: FungibleFaucetBuilder::symbol
    /// [`decimals`]: FungibleFaucetBuilder::decimals
    /// [`max_supply`]: FungibleFaucetBuilder::max_supply
    #[builder]
    pub fn new(
        name: TokenName,
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: AssetAmount,
        #[builder(default)] token_supply: AssetAmount,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        external_link: Option<ExternalLink>,
        #[builder(default)] is_description_mutable: bool,
        #[builder(default)] is_logo_uri_mutable: bool,
        #[builder(default)] is_external_link_mutable: bool,
        #[builder(default)] is_max_supply_mutable: bool,
    ) -> Result<FungibleFaucet, FungibleFaucetError> {
        let mut metadata = TokenMetadata::new(name);
        if let Some(desc) = description {
            metadata = metadata.with_description(desc, is_description_mutable);
        } else {
            metadata = metadata.with_description_mutable(is_description_mutable);
        }
        if let Some(uri) = logo_uri {
            metadata = metadata.with_logo_uri(uri, is_logo_uri_mutable);
        } else {
            metadata = metadata.with_logo_uri_mutable(is_logo_uri_mutable);
        }
        if let Some(link) = external_link {
            metadata = metadata.with_external_link(link, is_external_link_mutable);
        } else {
            metadata = metadata.with_external_link_mutable(is_external_link_mutable);
        }
        metadata = metadata.with_max_supply_mutable(is_max_supply_mutable);

        Self::new_validated(symbol, decimals, max_supply, token_supply, metadata)
    }
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

        if token_supply > max_supply {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply: token_supply.as_u64(),
                max_supply: max_supply.as_u64(),
            });
        }

        Ok(Self {
            token_supply,
            max_supply,
            decimals,
            symbol,
            metadata,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &FUNGIBLE_FAUCET_CODE
    }

    /// Returns the procedure root of the `mint_and_send` account procedure.
    pub fn mint_and_send_root() -> AccountProcedureRoot {
        *FUNGIBLE_FAUCET_MINT_AND_SEND
    }

    /// Returns the procedure root of the `receive_and_burn` account procedure.
    pub fn receive_and_burn_root() -> AccountProcedureRoot {
        *FUNGIBLE_FAUCET_RECEIVE_AND_BURN
    }

    /// Returns the [`StorageSlotName`] holding the token config word
    /// `[token_supply, max_supply, decimals, token_symbol]`.
    pub fn token_config_slot() -> &'static StorageSlotName {
        &TOKEN_CONFIG_SLOT
    }

    /// Returns the current token supply (amount issued).
    pub fn token_supply(&self) -> AssetAmount {
        self.token_supply
    }

    /// Returns the maximum token supply.
    pub fn max_supply(&self) -> AssetAmount {
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
    pub fn token_config_slot_value(&self) -> StorageSlot {
        let word = Word::new([
            self.token_supply.into(),
            self.max_supply.into(),
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
    pub fn with_token_supply(
        mut self,
        token_supply: AssetAmount,
    ) -> Result<Self, FungibleFaucetError> {
        if token_supply > self.max_supply {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply: token_supply.as_u64(),
                max_supply: self.max_supply.as_u64(),
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
        let max_supply = AssetAmount::try_from(max_supply).map_err(|_| {
            FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply.as_canonical_u64(),
                max: AssetAmount::MAX.as_u64(),
            }
        })?;
        let token_supply = AssetAmount::try_from(token_supply).map_err(|_| {
            FungibleFaucetError::MaxSupplyTooLarge {
                actual: token_supply.as_canonical_u64(),
                max: AssetAmount::MAX.as_u64(),
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

        AccountComponent::new(FungibleFaucet::code().clone(), storage_slots, component_metadata)
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
/// - `storage_mode`: typically [`AccountStorageMode::Public`] for basic or network faucets.
/// - `auth_method`: typically [`AuthMethod::SingleSig`] for basic faucets, or
///   [`AuthMethod::NetworkAccount`] for network-style faucets. [`AuthMethod::NoAuth`] is also
///   accepted for unauthenticated faucets.
/// - `access_control`: [`AccessControl::AuthControlled`] for auth-only faucets, or
///   [`AccessControl::Ownable2Step`] / [`AccessControl::Rbac`] for owner-controlled faucets.
/// - `token_policy_manager`: the unified [`TokenPolicyManager`] holding both mint and burn policy.
///
/// The faucet itself, including all token metadata, is provided in the `faucet` parameter (see
/// [`FungibleFaucet::builder`]).
pub fn create_fungible_faucet(
    init_seed: [u8; 32],
    faucet: FungibleFaucet,
    storage_mode: AccountStorageMode,
    auth_method: AuthMethod,
    access_control: AccessControl,
    token_policy_manager: TokenPolicyManager,
) -> Result<Account, FungibleFaucetError> {
    let mint_proc_root = FungibleFaucet::mint_and_send_root();

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
        AuthMethod::NetworkAccount { allowed_script_roots } => {
            AuthNetworkAccount::with_allowlist(allowed_script_roots)
                .map_err(|err| {
                    FungibleFaucetError::UnsupportedAuthMethod(alloc::format!(
                        "invalid network account allowlist: {err}"
                    ))
                })?
                .into()
        },
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
