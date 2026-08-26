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
    AccountCodeInterface,
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    AccountStorage,
    AccountType,
    AssetCallbackFlag,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::TokenSymbol;
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
use crate::account::auth::{AuthSingleSig, NetworkAccount};
use crate::account::faucets::registers_owner_only_policy;
use crate::account::fees::FeePolicyManager;
use crate::account::policies::TokenPolicyManager;
use crate::note::{BurnNote, MintNote};
use crate::procedure_root;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Storage slot holding the token symbol word `[symbol, 0, 0, 0]` for a [`NonFungibleFaucet`].
pub(crate) static SYMBOL_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::non_fungible::symbol")
        .expect("storage slot name should be valid")
});

/// Storage slot holding the asset-status registry map (`[token_id_suffix, token_id_prefix, 0, 0]`
/// -> `[status, 0, 0, 0]`) for a [`NonFungibleFaucet`].
pub(crate) static ASSET_STATUS_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::faucets::non_fungible::asset_status")
        .expect("storage slot name should be valid")
});

// ASSET STATUS
// ================================================================================================

// On-chain status codes stored at element 0 of the asset-status registry value. These must match
// the `STATUS_ISSUED` / `STATUS_BURNED` constants in the non-fungible faucet MASM.
const STATUS_ISSUED: u8 = 1;
const STATUS_BURNED: u8 = 2;

/// The issuance status of a non-fungible asset within a [`NonFungibleFaucet`].
///
/// Mirrors the on-chain `get_asset_status` procedure: the faucet's asset-status registry maps each
/// token ID to `Issued` or `Burned`; a token ID that was never issued is absent from the registry
/// and reported as `NotIssued`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetStatus {
    /// The token ID has never been issued by this faucet.
    NotIssued,
    /// An NFT has been issued for the token ID and has not been burned.
    Issued,
    /// The token ID was issued and later burned; it is permanently consumed and can never be
    /// issued again.
    Burned,
}

impl TryFrom<u8> for AssetStatus {
    type Error = NonFungibleFaucetError;

    /// Builds an [`AssetStatus`] from the raw status code held in element 0 of the registry value
    /// word (0 = not issued, 1 = issued, 2 = burned).
    fn try_from(status: u8) -> Result<Self, Self::Error> {
        match status {
            0 => Ok(Self::NotIssued),
            STATUS_ISSUED => Ok(Self::Issued),
            STATUS_BURNED => Ok(Self::Burned),
            other => Err(NonFungibleFaucetError::InvalidAssetStatus { status: other.into() }),
        }
    }
}

// NON-FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

account_component_code!(
    NON_FUNGIBLE_FAUCET_CODE,
    "miden-standards-faucets-non-fungible-faucet.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`NonFungibleFaucet::NAME`], which mirrors the standards-side MASM module path.
const NON_FUNGIBLE_FAUCET_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::non_fungible_faucet";

procedure_root!(
    NON_FUNGIBLE_FAUCET_MINT_AND_SEND,
    NON_FUNGIBLE_FAUCET_LIBRARY_PATH,
    NonFungibleFaucet::MINT_AND_SEND_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_RECEIVE_AND_BURN,
    NON_FUNGIBLE_FAUCET_LIBRARY_PATH,
    NonFungibleFaucet::RECEIVE_AND_BURN_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_SET_DESCRIPTION,
    NON_FUNGIBLE_FAUCET_LIBRARY_PATH,
    NonFungibleFaucet::SET_DESCRIPTION_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_SET_LOGO_URI,
    NON_FUNGIBLE_FAUCET_LIBRARY_PATH,
    NonFungibleFaucet::SET_LOGO_URI_PROC_NAME,
    NonFungibleFaucet::code()
);

procedure_root!(
    NON_FUNGIBLE_FAUCET_SET_CONTRACT_URI,
    NON_FUNGIBLE_FAUCET_LIBRARY_PATH,
    NonFungibleFaucet::SET_CONTRACT_URI_PROC_NAME,
    NonFungibleFaucet::code()
);

/// An [`AccountComponent`] implementing a non-fungible (NFT) faucet.
///
/// The asset value is an opaque word chosen by the caller. By convention the minter sets it to the
/// off-chain commitment [`compute_asset_commitment`] produces, but the faucet validates neither
/// that construction nor knowledge of a preimage - see that method's documentation.
///
/// The NFT's token ID is `(hash0, hash1)` - the asset class the protocol derives from the value's
/// first two elements, which uniquely identifies each NFT within the faucet. The one property
/// enforced on-chain is token ID uniqueness, via an asset-status registry keyed by
/// `[hash0, hash1, 0, 0]`: a token ID can be issued at most once, and once burned it is permanently
/// consumed. Which values may be issued is decided entirely by the active mint policy, which
/// receives the full asset value; a permissive policy such as `allow_all` lets any caller claim any
/// token ID.
///
/// It re-exports the procedures from `miden::standards::faucets::non_fungible` plus the shared
/// token metadata accessors. The procedures are:
/// - `mint_and_send`, which mints an NFT for a commitment and creates a note for the recipient.
/// - `receive_and_burn`, which receives the NFT from the active note and burns it.
/// - `get_symbol`, `get_asset_status`, and the metadata accessors/setters (see the embedded
///   [`TokenMetadata`]).
///
/// `mint_and_send` is gated by the active mint policy from the associated [`TokenPolicyManager`];
/// `receive_and_burn` is gated by the active burn policy.
///
/// [`compute_asset_commitment`]: NonFungibleFaucet::compute_asset_commitment
#[derive(Debug, Clone)]
pub struct NonFungibleFaucet {
    symbol: TokenSymbol,
    /// Embeds name, optional fields, and mutability flags.
    metadata: TokenMetadata,
}

#[bon::bon]
impl NonFungibleFaucet {
    /// Returns a builder for [`NonFungibleFaucet`].
    ///
    /// Required setters: [`name`], [`symbol`]. Optional string fields default to `None`;
    /// mutability flags default to `false`. The collection metadata pointer is named
    /// `contract_uri` (it reuses the shared `external_link` storage).
    ///
    /// [`name`]: NonFungibleFaucetBuilder::name
    /// [`symbol`]: NonFungibleFaucetBuilder::symbol
    #[builder]
    pub fn new(
        name: TokenName,
        symbol: TokenSymbol,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        contract_uri: Option<ExternalLink>,
        #[builder(default)] is_description_mutable: bool,
        #[builder(default)] is_logo_uri_mutable: bool,
        #[builder(default)] is_contract_uri_mutable: bool,
    ) -> NonFungibleFaucet {
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

        Self { symbol, metadata }
    }
}

impl NonFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::non_fungible";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    const MINT_AND_SEND_PROC_NAME: &'static str = "mint_and_send";
    const RECEIVE_AND_BURN_PROC_NAME: &'static str = "receive_and_burn";
    const SET_DESCRIPTION_PROC_NAME: &'static str = "set_description";
    const SET_LOGO_URI_PROC_NAME: &'static str = "set_logo_uri";
    const SET_CONTRACT_URI_PROC_NAME: &'static str = "set_contract_uri";

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

    /// Returns the [`StorageSlotName`] holding the token symbol word.
    pub fn symbol_slot() -> &'static StorageSlotName {
        &SYMBOL_SLOT
    }

    /// Returns the [`StorageSlotName`] holding the asset-status registry map.
    pub fn asset_status_slot() -> &'static StorageSlotName {
        &ASSET_STATUS_SLOT
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

    /// Computes the off-chain asset commitment `hash(user_data, salt)` that the minter is expected
    /// to use as the NFT asset value.
    ///
    /// This must be computed off-chain: computing it on-chain would leak the salt and make the
    /// underlying `user_data` invertible. The faucet never sees `user_data` or `salt` — only
    /// this commitment word.
    ///
    /// Using this helper is a convention, not an enforced property. `mint_and_send` accepts any
    /// word: it cannot check that a value is a hash output, that a salt was used, or that the
    /// minter knows a preimage. Consequently a minted asset value attests to nothing the faucet
    /// verified. Integrators that rely on the value identifying specific off-chain data must
    /// recompute the commitment from the `user_data` and `salt` they received and compare it to
    /// the on-chain asset value themselves. Where issuance itself must be controlled - e.g. so a
    /// published commitment cannot be claimed by a third party - install a restrictive mint policy
    /// such as `owner_only` rather than `allow_all`; the policy hook receives the full asset value.
    pub fn compute_asset_commitment(user_data: &[u8], salt: Word) -> Word {
        let data_digest = Hasher::hash(user_data);
        Hasher::merge(&[data_digest, salt])
    }

    /// Reads the issuance [`AssetStatus`] of the token ID derived from `asset_commitment` (the
    /// asset value, by convention produced by [`compute_asset_commitment`]) from the faucet
    /// account's `storage`.
    ///
    /// The status is keyed by the token ID - elements 0 and 1 of the value - so two values that
    /// differ only in elements 2 and 3 share a single status entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the asset-status slot cannot be read or holds an invalid status code.
    ///
    /// [`compute_asset_commitment`]: NonFungibleFaucet::compute_asset_commitment
    pub fn get_asset_status(
        storage: &AccountStorage,
        asset_commitment: Word,
    ) -> Result<AssetStatus, NonFungibleFaucetError> {
        // The registry key is the token ID (commitment elements 0 and 1) padded to a word, matching
        // the `create_status_key` procedure in the non-fungible faucet MASM.
        let key = StorageMapKey::new(Word::new([
            asset_commitment[0],
            asset_commitment[1],
            Felt::ZERO,
            Felt::ZERO,
        ]));

        let status_word = storage.get_map_item(Self::asset_status_slot(), key).map_err(|err| {
            TokenMetadataError::StorageLookupFailed {
                slot_name: Self::asset_status_slot().clone(),
                source: err,
            }
        })?;

        let raw_status = status_word[0].as_canonical_u64();
        let status_code = u8::try_from(raw_status)
            .map_err(|_| NonFungibleFaucetError::InvalidAssetStatus { status: raw_status })?;
        AssetStatus::try_from(status_code)
    }

    /// Returns the storage slot schema for the token symbol slot.
    pub fn symbol_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::symbol_slot().clone(),
            StorageSlotSchema::value(
                "Token symbol",
                [
                    FeltSchema::felt("symbol"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    /// Returns the storage slot schema for the asset-status registry map.
    pub fn asset_status_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::asset_status_slot().clone(),
            StorageSlotSchema::map(
                "Asset status registry. Key is the token ID padded to a word \
                 `[token_id_suffix, token_id_prefix, 0, 0]`; value is the status (0 = not issued, \
                 1 = issued, 2 = burned) padded to a word `[status, 0, 0, 0]`.",
                SchemaType::native_word(),
                SchemaType::native_felt(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let mut schema_entries = vec![Self::symbol_slot_schema(), Self::asset_status_slot_schema()];
        schema_entries.extend(TokenMetadata::storage_schema());

        let storage_schema =
            StorageSchema::new(schema_entries).expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Non-fungible faucet component bundling minting, burning, status, and metadata",
            )
            .with_storage_schema(storage_schema)
    }

    /// Returns the storage slots produced by this faucet (token symbol word + empty asset-status
    /// map + name + mutability config + description + logo URI + contract URI).
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let mut slots: Vec<StorageSlot> = Vec::new();
        slots.push(self.symbol_slot_value());
        slots.push(StorageSlot::with_map(Self::asset_status_slot().clone(), StorageMap::default()));
        slots.extend(self.metadata.into_storage_slots());
        slots
    }

    /// Returns the single storage slot for the token symbol word.
    pub fn symbol_slot_value(&self) -> StorageSlot {
        let word = Word::new([self.symbol.clone().into(), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
        StorageSlot::with_value(Self::symbol_slot().clone(), word)
    }

    // INTERFACE EXTRACTION
    // --------------------------------------------------------------------------------------------

    /// Checks that the account exposes the full non-fungible faucet interface before
    /// reconstructing it from storage.
    ///
    /// The storage slots alone are enough to rebuild the struct, but the conversion should only
    /// succeed when the account actually installs the [`NonFungibleFaucet`] component, so callers
    /// can rely on it to answer "does this account have the non-fungible faucet interface?".
    fn try_from_interface(
        interface: AccountCodeInterface,
        storage: &AccountStorage,
    ) -> Result<Self, NonFungibleFaucetError> {
        if !interface.contains(NonFungibleFaucet::code().procedure_roots()) {
            return Err(NonFungibleFaucetError::NotANonFungibleFaucetAccount);
        }

        NonFungibleFaucet::try_from(storage)
    }

    /// Reconstructs from the token symbol word and the embedded [`TokenMetadata`].
    pub(crate) fn from_symbol_word_and_token_metadata(
        word: Word,
        metadata: TokenMetadata,
    ) -> Result<Self, NonFungibleFaucetError> {
        let [symbol, ..] = *word;
        let symbol =
            TokenSymbol::try_from(symbol).map_err(TokenMetadataError::InvalidTokenSymbol)?;

        Ok(Self { symbol, metadata })
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
        let symbol_word = storage.get_item(Self::symbol_slot()).map_err(|err| {
            TokenMetadataError::StorageLookupFailed {
                slot_name: Self::symbol_slot().clone(),
                source: err,
            }
        })?;

        let token_metadata = TokenMetadata::try_from_storage(storage)?;

        Self::from_symbol_word_and_token_metadata(symbol_word, token_metadata)
    }
}

impl TryFrom<&Account> for NonFungibleFaucet {
    type Error = NonFungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        NonFungibleFaucet::try_from_interface(account.code_interface(), account.storage())
    }
}

// FACTORY
// ================================================================================================

/// Creates a new **user-account** non-fungible faucet. The account's auth component is the sole
/// gate for authority-protected setters ([`Authority::AuthControlled`] is installed directly).
///
/// The caller passes a fully-configured [`AuthSingleSig`]. Every authority-gated setter
/// (`mint_and_send`, the metadata setters, the policy setters, and `pause` / `unpause`) requires a
/// signature.
///
/// # Errors
///
/// Returns [`NonFungibleFaucetError::OwnerOnlyPolicyWithoutOwnable2Step`] if
/// `token_policy_manager` registers an owner-gated mint or burn policy: this factory installs no
/// `Ownable2Step` component, so such a policy would abort on every dispatch.
pub fn create_user_non_fungible_faucet(
    init_seed: [u8; 32],
    faucet: NonFungibleFaucet,
    auth_component: AuthSingleSig,
    token_policy_manager: TokenPolicyManager,
    account_type: AccountType,
) -> Result<Account, NonFungibleFaucetError> {
    // TODO: remove with the general component dependency mechanism, see
    // `super::registers_owner_only_policy`.
    if registers_owner_only_policy(&token_policy_manager) {
        return Err(NonFungibleFaucetError::OwnerOnlyPolicyWithoutOwnable2Step);
    }

    let asset_callbacks = AssetCallbackFlag::from(token_policy_manager.has_transfer_policy());
    AccountBuilder::new(init_seed)
        .account_type(account_type)
        .with_asset_callbacks(asset_callbacks)
        .with_component(auth_component)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(token_policy_manager)
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .build()
        .map_err(NonFungibleFaucetError::AccountCreationFailed)
}

/// Creates a new **network-style** non-fungible faucet. The account is always
/// [`AccountType::Public`]. Setter gating is enforced in-procedure by the owner / role check
/// installed via `access_control` ([`AccessControl::Ownable2Step`] or [`AccessControl::Rbac`]).
///
/// The factory builds the account via [`NetworkAccount::builder`] with a note allowlist covering
/// the faucet's own [`MintNote`] and [`BurnNote`] scripts; the builder also allowlists the
/// canonical expiration setter
/// ([`ExpirationTransactionScript`](crate::tx_script::ExpirationTransactionScript)) so the
/// network can bound its own transactions' expiry.
///
/// # Errors
///
/// Returns [`NonFungibleFaucetError::OwnerOnlyPolicyWithoutOwnable2Step`] if
/// `token_policy_manager` registers an owner-gated mint or burn policy while `access_control` is
/// [`AccessControl::Rbac`], which installs no `Ownable2Step` component for the policy to read the
/// owner from.
pub fn create_network_non_fungible_faucet(
    init_seed: [u8; 32],
    faucet: NonFungibleFaucet,
    access_control: AccessControl,
    token_policy_manager: TokenPolicyManager,
    fee_policy_manager: FeePolicyManager,
) -> Result<Account, NonFungibleFaucetError> {
    // TODO: remove with the general component dependency mechanism, see
    // `super::registers_owner_only_policy`.
    if registers_owner_only_policy(&token_policy_manager)
        && !matches!(access_control, AccessControl::Ownable2Step { .. })
    {
        return Err(NonFungibleFaucetError::OwnerOnlyPolicyWithoutOwnable2Step);
    }

    let note_allowlist = [MintNote::script_root(), BurnNote::script_root()].into_iter().collect();
    let asset_callbacks = AssetCallbackFlag::from(token_policy_manager.has_transfer_policy());

    NetworkAccount::builder(init_seed, note_allowlist, fee_policy_manager)
        .expect("MintNote + BurnNote allowlist is non-empty")
        .with_asset_callbacks(asset_callbacks)
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .with_component(Pausable::unpaused())
        .with_component(PausableManager)
        .build()
        .map_err(NonFungibleFaucetError::AccountCreationFailed)
}
