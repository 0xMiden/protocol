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
    AccountComponent,
    AccountStorage,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::{FungibleFaucetError, TokenMetadataError};
use crate::account::components::basic_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::metadata::{
    DESCRIPTION_SLOTS,
    Description,
    EXTERNAL_LINK_SLOTS,
    ExternalLink,
    LOGO_URI_SLOTS,
    LogoURI,
    MUTABILITY_CONFIG_SLOT,
    NAME_SLOTS,
    TokenMetadata,
    TokenName,
};
use crate::procedure_digest;

// CONSTANTS
// ================================================================================================

/// Storage slot holding the token config word `[token_supply, max_supply, decimals,
/// token_symbol]` for a [`BasicFungibleFaucet`].
pub(crate) static TOKEN_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::fungible::token_config")
        .expect("storage slot name should be valid")
});

/// Schema type string for the token symbol field in the token config slot.
const TOKEN_SYMBOL_TYPE: &str = "miden::standards::faucets::fungible::token_symbol";

// BASIC FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `mint_and_send` procedure of the Basic Fungible Faucet only once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_MINT_AND_SEND,
    BasicFungibleFaucet::NAME,
    BasicFungibleFaucet::MINT_PROC_NAME,
    basic_fungible_faucet_library
);

// Initialize the digest of the `receive_and_burn` procedure of the Basic Fungible Faucet only
// once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_RECEIVE_AND_BURN,
    BasicFungibleFaucet::NAME,
    BasicFungibleFaucet::RECEIVE_AND_BURN_PROC_NAME,
    basic_fungible_faucet_library
);

/// An [`AccountComponent`] implementing a fungible faucet.
///
/// This component bundles the asset minting/burning procedures and the token metadata
/// (name, description, logo URI, external link) together. Whether the faucet behaves like a
/// "basic" public faucet or a network-style faucet is a function of the surrounding account
/// configuration (storage mode, auth component, access control component, and policy manager
/// configuration), not of the faucet component itself.
///
/// It re-exports the procedures from `miden::standards::faucets::basic_fungible`. When linking
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
pub struct BasicFungibleFaucet {
    token_supply: Felt,
    max_supply: Felt,
    decimals: u8,
    symbol: TokenSymbol,
    /// Embeds name, optional fields, and mutability flags.
    metadata: TokenMetadata,
}

impl BasicFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::basic_fungible_faucet";

    /// The maximum number of decimals supported.
    pub const MAX_DECIMALS: u8 = 12;

    const MINT_PROC_NAME: &'static str = "mint_and_send";
    const RECEIVE_AND_BURN_PROC_NAME: &'static str = "receive_and_burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a builder for [`BasicFungibleFaucet`] with the required fields set.
    ///
    /// This is the main entry point for constructing a faucet; optional fields and the initial
    /// token supply can be set via the builder before calling
    /// [`BasicFungibleFaucetBuilder::build`].
    ///
    /// # Parameters
    ///
    /// - `name`: display name (at most 32 UTF-8 bytes).
    /// - `symbol`: token symbol.
    /// - `decimals`: decimal precision (0–12).
    /// - `max_supply`: maximum token supply (0–[`FungibleAsset::MAX_AMOUNT`], expressed as a
    ///   `u64`).
    pub fn builder(
        name: TokenName,
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: u64,
    ) -> BasicFungibleFaucetBuilder {
        BasicFungibleFaucetBuilder::new(name, symbol, decimals, max_supply)
    }

    /// Validates all fields and constructs a [`BasicFungibleFaucet`].
    ///
    /// This is the single point where `Self { ... }` is constructed. All other constructors
    /// delegate here.
    pub(crate) fn new_validated(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: u64,
        token_supply: u64,
        metadata: TokenMetadata,
    ) -> Result<Self, FungibleFaucetError> {
        if decimals > Self::MAX_DECIMALS {
            return Err(FungibleFaucetError::TooManyDecimals {
                actual: decimals as u64,
                max: Self::MAX_DECIMALS,
            });
        }

        if max_supply > FungibleAsset::MAX_AMOUNT {
            return Err(FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply,
                max: FungibleAsset::MAX_AMOUNT,
            });
        }

        if token_supply > max_supply {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply,
                max_supply,
            });
        }

        // SAFETY: max_supply and token_supply are validated above to be <= MAX_AMOUNT (2^63 - 1),
        // which is well below the Goldilocks prime, so Felt::new will not wrap.
        Ok(Self {
            token_supply: Felt::new(token_supply),
            max_supply: Felt::new(max_supply),
            decimals,
            symbol,
            metadata,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the digest of the `mint_and_send` account procedure.
    pub fn mint_and_send_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_MINT_AND_SEND
    }

    /// Returns the digest of the `receive_and_burn` account procedure.
    pub fn receive_and_burn_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_RECEIVE_AND_BURN
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

        // Name chunks (2 slots)
        for (i, slot) in NAME_SLOTS.iter().enumerate() {
            schema_entries.push((
                slot.clone(),
                StorageSlotSchema::value(
                    alloc::format!("Name chunk {i}"),
                    core::array::from_fn(|j| FeltSchema::felt(alloc::format!("data_{j}"))),
                ),
            ));
        }

        // Mutability config (1 slot)
        schema_entries.push((
            MUTABILITY_CONFIG_SLOT.clone(),
            StorageSlotSchema::value(
                "Mutability config",
                [
                    FeltSchema::bool("is_description_mutable"),
                    FeltSchema::bool("is_logo_uri_mutable"),
                    FeltSchema::bool("is_external_link_mutable"),
                    FeltSchema::bool("is_max_supply_mutable"),
                ],
            ),
        ));

        // Description, Logo URI, External link (7 slots each)
        for (label, slots) in [
            ("Description", DESCRIPTION_SLOTS.as_slice()),
            ("Logo URI", LOGO_URI_SLOTS.as_slice()),
            ("External link", EXTERNAL_LINK_SLOTS.as_slice()),
        ] {
            for (i, slot) in slots.iter().enumerate() {
                schema_entries.push((
                    slot.clone(),
                    StorageSlotSchema::value(
                        alloc::format!("{label} chunk {i}"),
                        core::array::from_fn(|j| FeltSchema::felt(alloc::format!("data_{j}"))),
                    ),
                ));
            }
        }

        let storage_schema =
            StorageSchema::new(schema_entries).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description(
                "Basic fungible faucet component bundling minting, burning, and token metadata",
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

    /// Checks that the account contains the basic fungible faucet interface.
    fn try_from_interface(
        interface: AccountInterface,
        _storage: &AccountStorage,
    ) -> Result<Self, FungibleFaucetError> {
        if !interface.components().contains(&AccountComponentInterface::BasicFungibleFaucet) {
            return Err(FungibleFaucetError::MissingBasicFungibleFaucetInterface);
        }

        BasicFungibleFaucet::try_from(_storage)
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

        Self::new_validated(
            symbol,
            decimals,
            max_supply.as_canonical_u64(),
            token_supply.as_canonical_u64(),
            metadata,
        )
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<BasicFungibleFaucet> for AccountComponent {
    fn from(faucet: BasicFungibleFaucet) -> Self {
        let component_metadata = BasicFungibleFaucet::component_metadata();
        let storage_slots = faucet.into_storage_slots();

        AccountComponent::new(basic_fungible_faucet_library(), storage_slots, component_metadata)
            .expect("basic fungible faucet component should satisfy the requirements of a valid account component")
    }
}

impl TryFrom<&AccountStorage> for BasicFungibleFaucet {
    type Error = FungibleFaucetError;

    /// Reconstructs [`BasicFungibleFaucet`] by reading all relevant storage slots: the token
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

impl TryFrom<Account> for BasicFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(&account);

        BasicFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for BasicFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(account);

        BasicFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

// BASIC FUNGIBLE FAUCET BUILDER
// ================================================================================================

/// Builder for [`BasicFungibleFaucet`] to avoid unwieldy optional arguments.
///
/// Required fields are set in [`Self::new`]; optional fields and token supply can be set via
/// chainable methods. Token supply defaults to zero.
///
/// # Example
///
/// ```
/// # use miden_protocol::asset::TokenSymbol;
/// # use miden_standards::account::faucets::BasicFungibleFaucet;
/// # use miden_standards::account::metadata::{Description, LogoURI, TokenName};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let name = TokenName::new("My Token")?;
/// let symbol = TokenSymbol::new("MTK")?;
/// let faucet = BasicFungibleFaucet::builder(name, symbol, 8, 1_000_000)
///     .token_supply(100)
///     .description(Description::new("A test token")?)
///     .logo_uri(LogoURI::new("https://example.com/logo.png")?)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct BasicFungibleFaucetBuilder {
    name: TokenName,
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: u64,
    token_supply: u64,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
    is_description_mutable: bool,
    is_logo_uri_mutable: bool,
    is_external_link_mutable: bool,
    is_max_supply_mutable: bool,
}

impl BasicFungibleFaucetBuilder {
    /// Creates a new builder with required fields. Token supply defaults to zero.
    ///
    /// # Parameters
    ///
    /// - `name`: display name (at most 32 UTF-8 bytes).
    /// - `symbol`: token symbol.
    /// - `decimals`: decimal precision; must be in the range `0..=12`.
    /// - `max_supply`: maximum number of tokens that can ever be minted; must be in the range
    ///   `0..=FungibleAsset::MAX_AMOUNT` (≤ 2^63 − 1). Expressed as a `u64` rather than a `Felt` to
    ///   avoid accidental out-of-range values.
    pub fn new(name: TokenName, symbol: TokenSymbol, decimals: u8, max_supply: u64) -> Self {
        Self {
            name,
            symbol,
            decimals,
            max_supply,
            token_supply: 0,
            description: None,
            logo_uri: None,
            external_link: None,
            is_description_mutable: false,
            is_logo_uri_mutable: false,
            is_external_link_mutable: false,
            is_max_supply_mutable: false,
        }
    }

    /// Sets the initial token supply (default is zero).
    pub fn token_supply(mut self, token_supply: u64) -> Self {
        self.token_supply = token_supply;
        self
    }

    /// Sets the optional description.
    pub fn description(mut self, description: Description) -> Self {
        self.description = Some(description);
        self
    }

    /// Sets the optional logo URI.
    pub fn logo_uri(mut self, logo_uri: LogoURI) -> Self {
        self.logo_uri = Some(logo_uri);
        self
    }

    /// Sets the optional external link.
    pub fn external_link(mut self, external_link: ExternalLink) -> Self {
        self.external_link = Some(external_link);
        self
    }

    /// Sets whether the description can be updated by the owner.
    pub fn is_description_mutable(mut self, mutable: bool) -> Self {
        self.is_description_mutable = mutable;
        self
    }

    /// Sets whether the logo URI can be updated by the owner.
    pub fn is_logo_uri_mutable(mut self, mutable: bool) -> Self {
        self.is_logo_uri_mutable = mutable;
        self
    }

    /// Sets whether the external link can be updated by the owner.
    pub fn is_external_link_mutable(mut self, mutable: bool) -> Self {
        self.is_external_link_mutable = mutable;
        self
    }

    /// Sets whether the max supply can be updated by the owner.
    pub fn is_max_supply_mutable(mut self, mutable: bool) -> Self {
        self.is_max_supply_mutable = mutable;
        self
    }

    /// Builds [`BasicFungibleFaucet`].
    pub fn build(self) -> Result<BasicFungibleFaucet, FungibleFaucetError> {
        let mut token_metadata = TokenMetadata::new(self.name);
        if let Some(desc) = self.description {
            token_metadata = token_metadata.with_description(desc, self.is_description_mutable);
        } else {
            token_metadata = token_metadata.with_description_mutable(self.is_description_mutable);
        }
        if let Some(uri) = self.logo_uri {
            token_metadata = token_metadata.with_logo_uri(uri, self.is_logo_uri_mutable);
        } else {
            token_metadata = token_metadata.with_logo_uri_mutable(self.is_logo_uri_mutable);
        }
        if let Some(link) = self.external_link {
            token_metadata = token_metadata.with_external_link(link, self.is_external_link_mutable);
        } else {
            token_metadata =
                token_metadata.with_external_link_mutable(self.is_external_link_mutable);
        }
        token_metadata = token_metadata.with_max_supply_mutable(self.is_max_supply_mutable);

        BasicFungibleFaucet::new_validated(
            self.symbol,
            self.decimals,
            self.max_supply,
            self.token_supply,
            token_metadata,
        )
    }
}

// FACTORY
// ================================================================================================

use miden_protocol::account::{AccountBuilder, AccountStorageMode};

use crate::AuthMethod;
use crate::account::access::AccessControl;
use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig, NoAuth};
use crate::account::policies::TokenPolicyManager;

/// Creates a new fungible faucet account by composing the required components.
///
/// The behaviour of the resulting faucet (basic vs network-style) is determined entirely by the
/// combination of arguments passed in:
/// - `storage_mode`: typically [`AccountStorageMode::Public`] for basic faucets, or
///   [`AccountStorageMode::Network`] for network-style faucets.
/// - `auth_method`: typically [`AuthMethod::SingleSig`] for basic faucets, or
///   [`AuthMethod::NoAuth`] for network-style faucets.
/// - `access_control`: [`AccessControl::AuthControlled`] for auth-only faucets, or
///   [`AccessControl::Ownable2Step`] / [`AccessControl::Rbac`] for owner-controlled faucets. The
///   matching [`Authority`][crate::account::access::Authority] component is auto-installed by
///   [`AccessControl`].
/// - `token_policy_manager`: the unified [`TokenPolicyManager`] holding both mint and burn policy.
///
/// The faucet itself, including all token metadata, is provided in the `faucet` parameter (see
/// [`BasicFungibleFaucet::builder`]).
pub fn create_basic_fungible_faucet(
    init_seed: [u8; 32],
    faucet: BasicFungibleFaucet,
    storage_mode: AccountStorageMode,
    auth_method: AuthMethod,
    access_control: AccessControl,
    token_policy_manager: TokenPolicyManager,
) -> Result<Account, FungibleFaucetError> {
    let mint_proc_root = BasicFungibleFaucet::mint_and_send_digest();

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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
    use miden_protocol::asset::TokenSymbol;
    use miden_protocol::{Felt, Word};

    use super::*;
    use crate::account::auth::{AuthSingleSig, AuthSingleSigAcl};
    use crate::account::metadata::{Description, TokenName};
    use crate::account::policies::{BurnPolicyConfig, MintPolicyConfig, TokenPolicyManager};
    use crate::account::wallets::BasicWallet;

    #[test]
    fn faucet_contract_creation() {
        let pub_key_word = Word::new([Felt::ONE; 4]);
        let auth_method: AuthMethod = AuthMethod::SingleSig {
            approver: (pub_key_word.into(), AuthScheme::Falcon512Poseidon2),
        };

        // we need to use an initial seed to create the wallet account
        let init_seed: [u8; 32] = [
            90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85,
            183, 204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
        ];

        let max_supply = 123u64;
        let token_symbol_string = "POL";
        let token_symbol = TokenSymbol::try_from(token_symbol_string).unwrap();
        let token_name_string = "polygon";
        let description_string = "A polygon token";
        let decimals = 2u8;
        let storage_mode = AccountStorageMode::Private;

        let token_name = TokenName::new(token_name_string).unwrap();
        let description = Description::new(description_string).unwrap();
        let faucet =
            BasicFungibleFaucet::builder(token_name, token_symbol.clone(), decimals, max_supply)
                .description(description)
                .build()
                .unwrap();
        let faucet_account = create_basic_fungible_faucet(
            init_seed,
            faucet,
            storage_mode,
            auth_method,
            AccessControl::AuthControlled,
            TokenPolicyManager::new(MintPolicyConfig::AllowAll, BurnPolicyConfig::AllowAll),
        )
        .unwrap();

        // The falcon auth component's public key should be present.
        assert_eq!(
            faucet_account.storage().get_item(AuthSingleSigAcl::public_key_slot()).unwrap(),
            pub_key_word
        );

        // The config slot of the auth component stores:
        // [num_trigger_procs, allow_unauthorized_output_notes, allow_unauthorized_input_notes, 0].
        //
        // With 1 trigger procedure (mint_and_send), allow_unauthorized_output_notes=false, and
        // allow_unauthorized_input_notes=true, this should be [1, 0, 1, 0].
        assert_eq!(
            faucet_account.storage().get_item(AuthSingleSigAcl::config_slot()).unwrap(),
            [Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ZERO].into()
        );

        // The procedure root map should contain the mint_and_send procedure root.
        let mint_root = BasicFungibleFaucet::mint_and_send_digest();
        assert_eq!(
            faucet_account
                .storage()
                .get_map_item(
                    AuthSingleSigAcl::trigger_procedure_roots_slot(),
                    [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
                )
                .unwrap(),
            mint_root
        );

        // Check that faucet metadata was initialized to the given values.
        // Storage layout: [token_supply, max_supply, decimals, symbol]
        assert_eq!(
            faucet_account
                .storage()
                .get_item(BasicFungibleFaucet::token_config_slot())
                .unwrap(),
            [Felt::ZERO, Felt::new(123), Felt::new(2), token_symbol.into()].into()
        );

        // Check that name was stored
        let name_0 = faucet_account.storage().get_item(TokenMetadata::name_chunk_0_slot()).unwrap();
        let name_1 = faucet_account.storage().get_item(TokenMetadata::name_chunk_1_slot()).unwrap();
        let decoded_name = TokenName::try_from_words(&[name_0, name_1]).unwrap();
        assert_eq!(decoded_name.as_str(), token_name_string);
        let expected_desc_words = Description::new(description_string).unwrap().to_words();
        for (i, expected) in expected_desc_words.iter().enumerate() {
            let chunk =
                faucet_account.storage().get_item(TokenMetadata::description_slot(i)).unwrap();
            assert_eq!(chunk, *expected);
        }

        assert!(faucet_account.is_faucet());

        assert_eq!(faucet_account.account_type(), AccountType::FungibleFaucet);

        // Verify the faucet component can be extracted
        let _faucet_component = BasicFungibleFaucet::try_from(faucet_account.clone()).unwrap();
    }

    #[test]
    fn faucet_create_from_account() {
        // prepare the test data
        let mock_word = Word::from([0, 1, 2, 3u32]);
        let mock_public_key = PublicKeyCommitment::from(mock_word);
        let mock_seed = mock_word.as_bytes();

        // valid account
        let token_symbol = TokenSymbol::new("POL").expect("invalid token symbol");
        let faucet =
            BasicFungibleFaucet::builder(TokenName::new("POL").unwrap(), token_symbol, 10, 100u64)
                .build()
                .expect("failed to create faucet");

        let faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_component(faucet)
            .with_auth_component(AuthSingleSig::new(
                mock_public_key,
                AuthScheme::Falcon512Poseidon2,
            ))
            .build_existing()
            .expect("failed to create wallet account");

        let _basic_ff = BasicFungibleFaucet::try_from(faucet_account)
            .expect("basic fungible faucet creation failed");

        // invalid account: basic fungible faucet component is missing
        let invalid_faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(AuthSingleSig::new(
                mock_public_key,
                AuthScheme::Falcon512Poseidon2,
            ))
            // we need to add some other component so the builder doesn't fail
            .with_component(BasicWallet)
            .build_existing()
            .expect("failed to create wallet account");

        let err = BasicFungibleFaucet::try_from(invalid_faucet_account)
            .err()
            .expect("basic fungible faucet creation should fail");
        assert_matches!(err, FungibleFaucetError::MissingBasicFungibleFaucetInterface);
    }

    /// Check that the obtaining of the basic fungible faucet procedure digests does not panic.
    #[test]
    fn get_faucet_procedures() {
        let _mint_and_send_digest = BasicFungibleFaucet::mint_and_send_digest();
        let _receive_and_burn_digest = BasicFungibleFaucet::receive_and_burn_digest();
    }
}
