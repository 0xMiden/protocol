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
    AccountComponentName,
    AccountProcedureRoot,
    AccountStorage,
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

procedure_root!(
    FUNGIBLE_FAUCET_SET_MAX_SUPPLY,
    FungibleFaucet::NAME,
    FungibleFaucet::SET_MAX_SUPPLY_PROC_NAME,
    FungibleFaucet::code()
);

procedure_root!(
    FUNGIBLE_FAUCET_SET_DESCRIPTION,
    FungibleFaucet::NAME,
    FungibleFaucet::SET_DESCRIPTION_PROC_NAME,
    FungibleFaucet::code()
);

procedure_root!(
    FUNGIBLE_FAUCET_SET_LOGO_URI,
    FungibleFaucet::NAME,
    FungibleFaucet::SET_LOGO_URI_PROC_NAME,
    FungibleFaucet::code()
);

procedure_root!(
    FUNGIBLE_FAUCET_SET_EXTERNAL_LINK,
    FungibleFaucet::NAME,
    FungibleFaucet::SET_EXTERNAL_LINK_PROC_NAME,
    FungibleFaucet::code()
);

/// An [`AccountComponent`] implementing a fungible faucet.
///
/// This component bundles the asset minting/burning procedures and the token metadata
/// (name, description, logo URI, external link) together. Whether the faucet behaves like a
/// "basic" public faucet or a network-style faucet is a function of the surrounding account
/// configuration (account type, auth component, access control component, and policy manager
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

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// The maximum number of decimals supported.
    pub const MAX_DECIMALS: u8 = 12;

    const MINT_PROC_NAME: &'static str = "mint_and_send";
    const RECEIVE_AND_BURN_PROC_NAME: &'static str = "receive_and_burn";
    const SET_MAX_SUPPLY_PROC_NAME: &'static str = "set_max_supply";
    const SET_DESCRIPTION_PROC_NAME: &'static str = "set_description";
    const SET_LOGO_URI_PROC_NAME: &'static str = "set_logo_uri";
    const SET_EXTERNAL_LINK_PROC_NAME: &'static str = "set_external_link";

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

    /// Returns the procedure root of the `set_max_supply` account procedure.
    pub fn set_max_supply_root() -> AccountProcedureRoot {
        *FUNGIBLE_FAUCET_SET_MAX_SUPPLY
    }

    /// Returns the procedure root of the `set_description` account procedure.
    pub fn set_description_root() -> AccountProcedureRoot {
        *FUNGIBLE_FAUCET_SET_DESCRIPTION
    }

    /// Returns the procedure root of the `set_logo_uri` account procedure.
    pub fn set_logo_uri_root() -> AccountProcedureRoot {
        *FUNGIBLE_FAUCET_SET_LOGO_URI
    }

    /// Returns the procedure root of the `set_external_link` account procedure.
    pub fn set_external_link_root() -> AccountProcedureRoot {
        *FUNGIBLE_FAUCET_SET_EXTERNAL_LINK
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
    pub fn token_name(&self) -> &TokenName {
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

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Fungible faucet component bundling minting, burning, and token metadata",
            )
            .with_storage_schema(storage_schema)
    }

    /// Returns the storage slots produced by this faucet (token config word + name + mutability
    /// config + description + logo URI + external link + Pausable's `is_paused` flag).
    ///
    /// The `is_paused` slot is installed by FungibleFaucet itself (initial value: unpaused, zero
    /// word) so that the transversal pause guards baked into `execute_mint_policy`,
    /// `execute_burn_policy`, `check_policy` (allow_all / blocklist / allowlist) and the metadata
    /// setters can read it without panicking. Pause / unpause administration is exposed by the
    /// optional [`crate::account::access::pausable::PausableManager`] component.
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();
        slots.push(self.token_config_slot_value());
        slots.extend(self.metadata.into_storage_slots());
        slots.push(crate::account::access::pausable::PausableStorage::default().into_slot());
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

/// Every authority-gated procedure root that must require a signature when
/// [`AccessControl::AuthControlled`] is paired with [`AuthMethod::SingleSig`]. Includes
/// `mint_and_send` so that minting always requires a signature regardless of the access
/// control variant.
fn all_authority_gated_setter_roots() -> Vec<AccountProcedureRoot> {
    vec![
        FungibleFaucet::mint_and_send_root(),
        FungibleFaucet::set_max_supply_root(),
        FungibleFaucet::set_description_root(),
        FungibleFaucet::set_logo_uri_root(),
        FungibleFaucet::set_external_link_root(),
        TokenPolicyManager::set_mint_policy_root(),
        TokenPolicyManager::set_burn_policy_root(),
        TokenPolicyManager::set_send_policy_root(),
        TokenPolicyManager::set_receive_policy_root(),
    ]
}

/// Creates a new fungible faucet account by composing the required components.
///
/// Only specific `(access_control, auth_method)` combinations are supported; everything else
/// is rejected at the factory level. The valid combinations are:
///
/// - [`AccessControl::AuthControlled`] + [`AuthMethod::SingleSig`] — user-account faucet whose auth
///   component is the sole gate for every authority-protected setter.
/// - [`AccessControl::Ownable2Step`] / [`AccessControl::Rbac`] + [`AuthMethod::NetworkAccount`] or
///   [`AuthMethod::NoAuth`] — network-style faucet whose setter gate is enforced in-procedure by
///   the owner/role check.
///
/// All other pairings return a typed error:
/// [`FungibleFaucetError::IncompatibleAuthControlledAuth`] for `AuthControlled + NoAuth`, and
/// [`FungibleFaucetError::UnsupportedAccessControlAuthCombination`] for `AuthControlled +
/// NetworkAccount` and for `Ownable2Step`/`Rbac` + `SingleSig`. `Multisig` and `Unknown`
/// remain rejected for every variant via [`FungibleFaucetError::UnsupportedAuthMethod`].
pub fn create_fungible_faucet(
    init_seed: [u8; 32],
    faucet: FungibleFaucet,
    account_type: AccountType,
    auth_method: AuthMethod,
    access_control: AccessControl,
    token_policy_manager: TokenPolicyManager,
) -> Result<Account, FungibleFaucetError> {
    let auth_component = build_auth_component(&access_control, auth_method)?;

    let account = AccountBuilder::new(init_seed)
        .account_type(account_type)
        .with_auth_component(auth_component)
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}

/// Builds the account-level auth component, validating the `(access_control, auth_method)`
/// pair. See [`create_fungible_faucet`] for the list of supported combinations.
fn build_auth_component(
    access_control: &AccessControl,
    auth_method: AuthMethod,
) -> Result<AccountComponent, FungibleFaucetError> {
    match (access_control, auth_method) {
        // AuthControlled + SingleSig: the auth component is the sole setter gate, so it
        // must authenticate every authority-gated setter root.
        (
            AccessControl::AuthControlled,
            AuthMethod::SingleSig { approver: (pub_key, auth_scheme) },
        ) => Ok(AuthSingleSigAcl::new(
            pub_key,
            auth_scheme,
            AuthSingleSigAclConfig::new()
                .with_auth_trigger_procedures(all_authority_gated_setter_roots())
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into()),

        // AuthControlled + NetworkAccount: rejected.
        (AccessControl::AuthControlled, AuthMethod::NetworkAccount { .. }) => {
            Err(FungibleFaucetError::UnsupportedAccessControlAuthCombination(
                "NetworkAccount is only supported with AccessControl::Ownable2Step or \
                 AccessControl::Rbac (network-style faucets)"
                    .into(),
            ))
        },

        // AuthControlled + NoAuth: rejected. NoAuth cannot authenticate setters; under
        // AuthControlled the auth component is the sole gate, so this would leave every
        // authority-gated setter permissionless.
        (AccessControl::AuthControlled, AuthMethod::NoAuth) => {
            Err(FungibleFaucetError::IncompatibleAuthControlledAuth(
                "NoAuth cannot authenticate authority-gated setters".into(),
            ))
        },

        // Ownable2Step / Rbac + NetworkAccount: typical network-style faucet. Setter gating
        // is enforced in-procedure; the auth component restricts which note scripts can be
        // consumed against the faucet.
        (
            AccessControl::Ownable2Step { .. } | AccessControl::Rbac { .. },
            AuthMethod::NetworkAccount { allowed_script_roots },
        ) => Ok(AuthNetworkAccount::with_allowlist(allowed_script_roots)
            .map_err(|err| {
                FungibleFaucetError::UnsupportedAuthMethod(alloc::format!(
                    "invalid network account allowlist: {err}"
                ))
            })?
            .into()),

        // Ownable2Step / Rbac + NoAuth: valid; the setter gate is the in-procedure owner /
        // role check, so the account-level auth can legitimately be NoAuth.
        (AccessControl::Ownable2Step { .. } | AccessControl::Rbac { .. }, AuthMethod::NoAuth) => {
            Ok(NoAuth::new().into())
        },

        // Ownable2Step / Rbac + SingleSig: rejected. SingleSig is for user-account faucets
        // (AuthControlled); under owner/role-gated faucets it duplicates the setter check
        // with a per-tx signature that doesn't add security.
        (
            AccessControl::Ownable2Step { .. } | AccessControl::Rbac { .. },
            AuthMethod::SingleSig { .. },
        ) => Err(FungibleFaucetError::UnsupportedAccessControlAuthCombination(
            "SingleSig is only supported with AccessControl::AuthControlled; pair \
             Ownable2Step / Rbac with NetworkAccount or NoAuth instead"
                .into(),
        )),

        // Multisig and Unknown are not supported for any access control variant.
        (_, AuthMethod::Multisig { .. }) => Err(FungibleFaucetError::UnsupportedAuthMethod(
            "fungible faucets do not support Multisig authentication".into(),
        )),
        (_, AuthMethod::Unknown) => Err(FungibleFaucetError::UnsupportedAuthMethod(
            "fungible faucets cannot be created with Unknown authentication method".into(),
        )),
    }
}
