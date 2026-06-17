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
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Hasher, Word};

use super::{
    Description,
    ExternalLink,
    LogoURI,
    NonFungibleFaucetError,
    TokenMetadata,
    TokenMetadataError,
    TokenName,
};
use crate::account::access::{AccessControl, Authority, Pausable, PausableManager};
use crate::account::account_component_code;
use crate::account::auth::{AuthNetworkAccount, AuthSingleSigAcl};
use crate::account::policies::TokenPolicyManager;
use crate::note::{NonFungibleBurnNote, NonFungibleMintNote};
use crate::procedure_root;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Storage slot holding the token config word `[current_supply, max_supply, reserved, symbol]`
/// for a [`NonFungibleFaucet`].
pub(crate) static TOKEN_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::non_fungible::token_config")
        .expect("storage slot name should be valid")
});

/// Storage slot holding the asset-status registry map (`[hash0, hash1, 0, 0]` -> `[status, 0, 0,
/// 0]`) for a [`NonFungibleFaucet`].
pub(crate) static ASSET_STATUS_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::non_fungible::asset_status")
        .expect("storage slot name should be valid")
});

// NON-FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

account_component_code!(NON_FUNGIBLE_FAUCET_CODE, "faucets/non_fungible_faucet.masl");

procedure_root!(
    NON_FUNGIBLE_FAUCET_MINT_AND_SEND,
    NonFungibleFaucet::NAME,
    NonFungibleFaucet::MINT_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_RECEIVE_AND_BURN,
    NonFungibleFaucet::NAME,
    NonFungibleFaucet::RECEIVE_AND_BURN_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_SET_MAX_SUPPLY,
    NonFungibleFaucet::NAME,
    NonFungibleFaucet::SET_MAX_SUPPLY_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_SET_DESCRIPTION,
    NonFungibleFaucet::NAME,
    NonFungibleFaucet::SET_DESCRIPTION_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_SET_LOGO_URI,
    NonFungibleFaucet::NAME,
    NonFungibleFaucet::SET_LOGO_URI_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_SET_CONTRACT_URI,
    NonFungibleFaucet::NAME,
    NonFungibleFaucet::SET_CONTRACT_URI_PROC_NAME,
    NonFungibleFaucet::code()
);

/// An [`AccountComponent`] implementing a non-fungible (NFT) faucet.
///
/// The asset value is the off-chain commitment `hash(user_data, salt)`; the asset identity is
/// `(hash0, hash1)`. Uniqueness is enforced on-chain by an asset-status registry keyed by
/// `[hash0, hash1, 0, 0]`: a commitment can be issued at most once, and once burned it is
/// permanently consumed.
///
/// It re-exports the procedures from `miden::standards::faucets::non_fungible` plus the shared
/// token metadata accessors. The procedures are:
/// - `mint_and_send`, which mints an NFT for a commitment and creates a note for the recipient.
/// - `receive_and_burn`, which receives the NFT from the active note and burns it.
/// - `get_asset_status`, the token config accessors, the owner-gated `set_max_supply`, and the
///   metadata accessors/setters (see the embedded [`TokenMetadata`]).
///
/// `mint_and_send` is gated by the active mint policy from the associated [`TokenPolicyManager`];
/// `receive_and_burn` is gated by the active burn policy.
#[derive(Debug, Clone)]
pub struct NonFungibleFaucet {
    current_supply: AssetAmount,
    max_supply: AssetAmount,
    symbol: TokenSymbol,
    /// Embeds name, optional fields, and mutability flags.
    metadata: TokenMetadata,
}

#[bon::bon]
impl NonFungibleFaucet {
    /// Returns a builder for [`NonFungibleFaucet`].
    ///
    /// Required setters: [`name`], [`symbol`]. `max_supply` defaults to `0` (unlimited). Optional
    /// string fields default to `None`; mutability flags default to `false`. The collection
    /// metadata pointer is named `contract_uri` (it reuses the shared `external_link` storage).
    ///
    /// [`name`]: NonFungibleFaucetBuilder::name
    /// [`symbol`]: NonFungibleFaucetBuilder::symbol
    #[builder]
    pub fn new(
        name: TokenName,
        symbol: TokenSymbol,
        #[builder(default)] max_supply: AssetAmount,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        contract_uri: Option<ExternalLink>,
        #[builder(default)] is_description_mutable: bool,
        #[builder(default)] is_logo_uri_mutable: bool,
        #[builder(default)] is_contract_uri_mutable: bool,
        #[builder(default)] is_max_supply_mutable: bool,
    ) -> Result<NonFungibleFaucet, NonFungibleFaucetError> {
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
        if let Some(link) = contract_uri {
            metadata = metadata.with_external_link(link, is_contract_uri_mutable);
        } else {
            metadata = metadata.with_external_link_mutable(is_contract_uri_mutable);
        }
        metadata = metadata.with_max_supply_mutable(is_max_supply_mutable);

        Self::new_validated(symbol, AssetAmount::default(), max_supply, metadata)
    }
}

impl NonFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::non_fungible_faucet";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    const MINT_PROC_NAME: &'static str = "mint_and_send";
    const RECEIVE_AND_BURN_PROC_NAME: &'static str = "receive_and_burn";
    const SET_MAX_SUPPLY_PROC_NAME: &'static str = "set_max_supply";
    const SET_DESCRIPTION_PROC_NAME: &'static str = "set_description";
    const SET_LOGO_URI_PROC_NAME: &'static str = "set_logo_uri";
    const SET_CONTRACT_URI_PROC_NAME: &'static str = "set_contract_uri";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Validates all fields and constructs a [`NonFungibleFaucet`].
    pub(crate) fn new_validated(
        symbol: TokenSymbol,
        current_supply: AssetAmount,
        max_supply: AssetAmount,
        metadata: TokenMetadata,
    ) -> Result<Self, NonFungibleFaucetError> {
        if current_supply > max_supply && max_supply != AssetAmount::default() {
            return Err(NonFungibleFaucetError::CurrentSupplyExceedsMaxSupply {
                current_supply: current_supply.as_u64(),
                max_supply: max_supply.as_u64(),
            });
        }

        Ok(Self {
            current_supply,
            max_supply,
            symbol,
            metadata,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &NON_FUNGIBLE_FAUCET_CODE
    }

    /// Returns the procedure root of the `mint_and_send` account procedure.
    pub fn mint_and_send_root() -> AccountProcedureRoot {
        *NON_FUNGIBLE_FAUCET_MINT_AND_SEND
    }

    /// Returns the procedure root of the `receive_and_burn` account procedure.
    pub fn receive_and_burn_root() -> AccountProcedureRoot {
        *NON_FUNGIBLE_FAUCET_RECEIVE_AND_BURN
    }

    /// Returns the procedure root of the `set_max_supply` account procedure. Authority-gated.
    pub fn set_max_supply_root() -> AccountProcedureRoot {
        *NON_FUNGIBLE_FAUCET_SET_MAX_SUPPLY
    }

    /// Returns the procedure root of the `set_description` account procedure. Authority-gated.
    pub fn set_description_root() -> AccountProcedureRoot {
        *NON_FUNGIBLE_FAUCET_SET_DESCRIPTION
    }

    /// Returns the procedure root of the `set_logo_uri` account procedure. Authority-gated.
    pub fn set_logo_uri_root() -> AccountProcedureRoot {
        *NON_FUNGIBLE_FAUCET_SET_LOGO_URI
    }

    /// Returns the procedure root of the `set_contract_uri` account procedure. Authority-gated.
    pub fn set_contract_uri_root() -> AccountProcedureRoot {
        *NON_FUNGIBLE_FAUCET_SET_CONTRACT_URI
    }

    /// Returns the [`StorageSlotName`] holding the token config word.
    pub fn token_config_slot() -> &'static StorageSlotName {
        &TOKEN_CONFIG_SLOT
    }

    /// Returns the [`StorageSlotName`] holding the asset-status registry map.
    pub fn asset_status_slot() -> &'static StorageSlotName {
        &ASSET_STATUS_SLOT
    }

    /// Returns the current (live) supply.
    pub fn current_supply(&self) -> AssetAmount {
        self.current_supply
    }

    /// Returns the maximum supply (0 = unlimited).
    pub fn max_supply(&self) -> AssetAmount {
        self.max_supply
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

    /// Returns the optional collection metadata pointer (`contract_uri`, stored in the shared
    /// `external_link` slot).
    pub fn contract_uri(&self) -> Option<&ExternalLink> {
        self.metadata.external_link()
    }

    /// Returns the storage slot schema for the token config slot.
    pub fn token_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::token_config_slot().clone(),
            StorageSlotSchema::value(
                "Token config",
                [
                    FeltSchema::felt("current_supply").with_default(Felt::ZERO),
                    FeltSchema::felt("max_supply"),
                    FeltSchema::felt("reserved").with_default(Felt::ZERO),
                    FeltSchema::felt("symbol"),
                ],
            ),
        )
    }

    /// Returns the storage slot schema for the asset-status registry map.
    pub fn asset_status_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::asset_status_slot().clone(),
            StorageSlotSchema::map(
                "Asset status registry: commitment (hash0, hash1) -> status",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let mut schema_entries =
            vec![Self::token_config_slot_schema(), Self::asset_status_slot_schema()];
        schema_entries.extend(TokenMetadata::storage_schema());

        let storage_schema =
            StorageSchema::new(schema_entries).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Non-fungible faucet component bundling minting, burning, status, and metadata",
            )
            .with_storage_schema(storage_schema)
    }

    /// Returns the storage slots produced by this faucet (token config word + empty asset-status
    /// map + name + mutability config + description + logo URI + contract URI).
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();
        slots.push(self.token_config_slot_value());
        slots.push(StorageSlot::with_map(
            Self::asset_status_slot().clone(),
            StorageMap::with_entries(vec![]).expect("empty asset status map should be valid"),
        ));
        slots.extend(self.metadata.into_storage_slots());
        slots
    }

    /// Returns the single storage slot for the token config word.
    pub fn token_config_slot_value(&self) -> StorageSlot {
        let word = Word::new([
            self.current_supply.into(),
            self.max_supply.into(),
            Felt::ZERO,
            self.symbol.clone().into(),
        ]);
        StorageSlot::with_value(Self::token_config_slot().clone(), word)
    }

    // INTERFACE EXTRACTION
    // --------------------------------------------------------------------------------------------

    /// Reconstructs from the token config word and the embedded [`TokenMetadata`].
    pub(crate) fn from_token_config_word_and_token_metadata(
        word: Word,
        metadata: TokenMetadata,
    ) -> Result<Self, NonFungibleFaucetError> {
        let [current_supply, max_supply, _reserved, symbol] = *word;
        let symbol =
            TokenSymbol::try_from(symbol).map_err(TokenMetadataError::InvalidTokenSymbol)?;
        let max_supply = AssetAmount::try_from(max_supply).map_err(|_| {
            NonFungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply.as_canonical_u64(),
                max: AssetAmount::MAX.as_u64(),
            }
        })?;
        let current_supply = AssetAmount::try_from(current_supply).map_err(|_| {
            NonFungibleFaucetError::MaxSupplyTooLarge {
                actual: current_supply.as_canonical_u64(),
                max: AssetAmount::MAX.as_u64(),
            }
        })?;

        Self::new_validated(symbol, current_supply, max_supply, metadata)
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<NonFungibleFaucet> for AccountComponent {
    fn from(faucet: NonFungibleFaucet) -> Self {
        let component_metadata = NonFungibleFaucet::component_metadata();
        let storage_slots = faucet.into_storage_slots();

        AccountComponent::new(NonFungibleFaucet::code().clone(), storage_slots, component_metadata)
            .expect("non-fungible faucet component should satisfy the requirements of a valid account component")
    }
}

impl TryFrom<&AccountStorage> for NonFungibleFaucet {
    type Error = NonFungibleFaucetError;

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

impl TryFrom<Account> for NonFungibleFaucet {
    type Error = NonFungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        NonFungibleFaucet::try_from(account.storage())
    }
}

impl TryFrom<&Account> for NonFungibleFaucet {
    type Error = NonFungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        NonFungibleFaucet::try_from(account.storage())
    }
}

// COMMITMENT HELPER
// ================================================================================================

/// Computes the off-chain asset commitment `hash(user_data, salt)` used as the NFT asset value.
///
/// This must be computed off-chain: computing it on-chain would leak the salt and make the
/// underlying `user_data` invertible. The faucet never sees `user_data` or `salt` — only this
/// commitment word.
pub fn compute_commitment(user_data: &[u8], salt: Word) -> Word {
    let data_digest = Hasher::hash(user_data);
    Hasher::merge(&[data_digest, salt])
}

// FACTORY
// ================================================================================================

/// Returns every authority-gated procedure root of a non-fungible faucet. Callers building the
/// [`AuthSingleSigAcl`] for [`create_user_non_fungible_faucet`] must register all of these as
/// trigger procedures, otherwise they become permissionless under [`Authority::AuthControlled`].
pub fn authority_gated_setter_roots() -> Vec<AccountProcedureRoot> {
    vec![
        NonFungibleFaucet::mint_and_send_root(),
        NonFungibleFaucet::set_max_supply_root(),
        NonFungibleFaucet::set_description_root(),
        NonFungibleFaucet::set_logo_uri_root(),
        NonFungibleFaucet::set_contract_uri_root(),
        TokenPolicyManager::set_mint_policy_root(),
        TokenPolicyManager::set_burn_policy_root(),
        TokenPolicyManager::set_send_policy_root(),
        TokenPolicyManager::set_receive_policy_root(),
        PausableManager::pause_root(),
        PausableManager::unpause_root(),
    ]
}

/// Creates a new **user-account** non-fungible faucet. The account's auth component is the sole
/// gate for authority-protected setters ([`Authority::AuthControlled`] is installed directly).
///
/// The caller passes a fully-configured [`AuthSingleSigAcl`]; its trigger procedure list must
/// cover every authority-gated setter (see [`authority_gated_setter_roots`]).
pub fn create_user_non_fungible_faucet(
    init_seed: [u8; 32],
    faucet: NonFungibleFaucet,
    auth_component: AuthSingleSigAcl,
    token_policy_manager: TokenPolicyManager,
    account_type: AccountType,
) -> Result<Account, NonFungibleFaucetError> {
    AccountBuilder::new(init_seed)
        .account_type(account_type)
        .with_auth_component(auth_component)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(token_policy_manager)
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .build()
        .map_err(NonFungibleFaucetError::AccountError)
}

/// Creates a new **network-style** non-fungible faucet. The account is always
/// [`AccountType::Public`]. Setter gating is enforced in-procedure by the owner / role check
/// installed via `access_control` ([`AccessControl::Ownable2Step`] or [`AccessControl::Rbac`]).
///
/// The factory builds the [`AuthNetworkAccount`] auth component internally with a note allowlist
/// covering the faucet's own [`NonFungibleMintNote`] and [`NonFungibleBurnNote`] scripts.
pub fn create_network_non_fungible_faucet(
    init_seed: [u8; 32],
    faucet: NonFungibleFaucet,
    access_control: AccessControl,
    token_policy_manager: TokenPolicyManager,
) -> Result<Account, NonFungibleFaucetError> {
    let note_allowlist = [NonFungibleMintNote::script_root(), NonFungibleBurnNote::script_root()]
        .into_iter()
        .collect();
    let auth_component = AuthNetworkAccount::with_allowed_notes(note_allowlist)
        .expect("non-fungible MintNote + BurnNote allowlist is non-empty");

    AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_auth_component(auth_component)
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .build()
        .map_err(NonFungibleFaucetError::AccountError)
}
