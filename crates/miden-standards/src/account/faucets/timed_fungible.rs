use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaTypeId,
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
use miden_protocol::asset::TokenSymbol;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, FieldElement, Word};

use super::token_metadata::TOKEN_SYMBOL_TYPE_ID;
use super::{FungibleFaucetError, TokenMetadata};
use crate::account::AuthScheme;
use crate::account::auth::{
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakAclConfig,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoAclConfig,
};
use crate::account::components::timed_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::procedure_digest;

// SLOT NAMES
// ================================================================================================

static SUPPLY_CONFIG_SLOT: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::supply::supply_limits::config")
        .expect("storage slot name should be valid")
});

// TIMED FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

procedure_digest!(
    TIMED_FUNGIBLE_FAUCET_DISTRIBUTE,
    TimedFungibleFaucet::DISTRIBUTE_PROC_NAME,
    timed_fungible_faucet_library
);

procedure_digest!(
    TIMED_FUNGIBLE_FAUCET_BURN,
    TimedFungibleFaucet::BURN_PROC_NAME,
    timed_fungible_faucet_library
);

/// An [`AccountComponent`] implementing a timed fungible faucet.
///
/// It reexports the procedures from `miden::standards::faucets::timed_fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `distribute`, which mints assets and creates a note for the provided recipient within the
///   allowed time window.
/// - `burn`, which burns the provided asset (respects burn-only mode).
///
/// This component supports accounts of type [`AccountType::FungibleFaucet`].
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Stores [`TokenMetadata`].
/// - [`Self::supply_config_slot`]: Stores supply config `[token_supply, max_supply,
///   distribution_end, burn_only]`.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct TimedFungibleFaucet {
    metadata: TokenMetadata,
    distribution_end: u32,
    burn_only: bool,
}

impl TimedFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::timed_fungible_faucet";

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = TokenMetadata::MAX_DECIMALS;

    const DISTRIBUTE_PROC_NAME: &str = "timed_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "timed_fungible_faucet::burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`TimedFungibleFaucet`] component from the given pieces of metadata and with
    /// an initial token supply of zero.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply parameter exceeds maximum possible amount for a fungible asset
    ///   ([`miden_protocol::asset::FungibleAsset::MAX_AMOUNT`])
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
        distribution_end: u32,
        burn_only: bool,
    ) -> Result<Self, FungibleFaucetError> {
        let metadata = TokenMetadata::new(symbol, decimals, max_supply)?;
        Ok(Self { metadata, distribution_end, burn_only })
    }

    /// Creates a new [`TimedFungibleFaucet`] component from the given [`TokenMetadata`].
    pub fn from_metadata(metadata: TokenMetadata, distribution_end: u32, burn_only: bool) -> Self {
        Self { metadata, distribution_end, burn_only }
    }

    /// Attempts to create a new [`TimedFungibleFaucet`] component from the associated account
    /// interface and storage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided [`AccountInterface`] does not contain a
    ///   [`AccountComponentInterface::TimedFungibleFaucet`] component.
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
        if !interface.components().contains(&AccountComponentInterface::TimedFungibleFaucet) {
            return Err(FungibleFaucetError::MissingTimedFungibleFaucetInterface);
        }

        let metadata = TokenMetadata::try_from(storage)?;

        // Read supply config: [token_supply, max_supply, distribution_end, burn_only]
        let config_word: Word = storage
            .get_item(TimedFungibleFaucet::supply_config_slot())
            .map_err(|err| FungibleFaucetError::StorageLookupFailed {
                slot_name: TimedFungibleFaucet::supply_config_slot().clone(),
                source: err,
            })?;

        let distribution_end = config_word[2].as_int() as u32;
        let burn_only = config_word[3].as_int() != 0;

        Ok(Self { metadata, distribution_end, burn_only })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`TimedFungibleFaucet`]'s metadata is stored.
    pub fn metadata_slot() -> &'static StorageSlotName {
        TokenMetadata::metadata_slot()
    }

    /// Returns the [`StorageSlotName`] where the supply configuration is stored.
    pub fn supply_config_slot() -> &'static StorageSlotName {
        &SUPPLY_CONFIG_SLOT
    }

    /// Returns the storage slot schema for the metadata slot.
    pub fn metadata_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        let token_symbol_type = SchemaTypeId::new(TOKEN_SYMBOL_TYPE_ID).expect("valid type id");
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

    /// Returns the storage slot schema for the supply config slot.
    pub fn supply_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::supply_config_slot().clone(),
            StorageSlotSchema::value(
                "Supply Config",
                [
                    FeltSchema::felt("token_supply").with_default(Felt::new(0)),
                    FeltSchema::felt("max_supply"),
                    FeltSchema::u32("distribution_end"),
                    FeltSchema::felt("burn_only_flag").with_default(Felt::new(0)),
                ],
            ),
        )
    }

    /// Returns the token metadata.
    pub fn metadata(&self) -> &TokenMetadata {
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
    pub fn max_supply(&self) -> Felt {
        self.metadata.max_supply()
    }

    /// Returns the token supply (in base units) of the faucet.
    pub fn token_supply(&self) -> Felt {
        self.metadata.token_supply()
    }

    /// Returns the block number at which distribution ends.
    pub fn distribution_end(&self) -> u32 {
        self.distribution_end
    }

    /// Returns whether the faucet is in burn-only mode after the distribution period.
    pub fn burn_only(&self) -> bool {
        self.burn_only
    }

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *TIMED_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *TIMED_FUNGIBLE_FAUCET_BURN
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the token_supply (in base units) of the timed fungible faucet.
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

impl From<TimedFungibleFaucet> for AccountComponent {
    fn from(faucet: TimedFungibleFaucet) -> Self {
        let metadata_slot: StorageSlot = faucet.metadata.into();

        let config_val = [
            Felt::ZERO, // token_supply starts at zero
            faucet.metadata.max_supply(),
            Felt::new(faucet.distribution_end as u64),
            Felt::new(faucet.burn_only as u64),
        ];

        let config_slot = StorageSlot::with_value(
            TimedFungibleFaucet::supply_config_slot().clone(),
            Word::new(config_val),
        );

        let storage_schema = StorageSchema::new([
            TimedFungibleFaucet::metadata_slot_schema(),
            TimedFungibleFaucet::supply_config_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(TimedFungibleFaucet::NAME)
            .with_description(
                "Timed fungible faucet component for time-bounded minting and burning tokens",
            )
            .with_supported_type(AccountType::FungibleFaucet)
            .with_storage_schema(storage_schema);

        AccountComponent::new(
            timed_fungible_faucet_library(),
            vec![metadata_slot, config_slot],
            metadata,
        )
        .expect("timed fungible faucet component should satisfy the requirements of a valid account component")
    }
}

impl TryFrom<Account> for TimedFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(&account);

        TimedFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for TimedFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(account);

        TimedFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

/// Creates a new faucet account with timed fungible faucet interface,
/// account storage type, specified authentication scheme, and provided metadata (token symbol,
/// decimals, max supply, distribution end block, burn-only flag).
///
/// The timed faucet interface exposes two procedures:
/// - `distribute`, which mints assets and creates a note for the provided recipient within the
///   distribution time window.
/// - `burn`, which burns the provided asset (respects burn-only mode).
///
/// The `distribute` procedure can be called from a transaction script and requires authentication
/// via the specified authentication scheme. The `burn` procedure can only be called from a note
/// script and requires the calling note to contain the asset to be burned.
pub fn create_timed_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    distribution_end: u32,
    burn_only: bool,
    storage_mode: AccountStorageMode,
    auth_scheme: AuthScheme,
) -> Result<Account, FungibleFaucetError> {
    let distribute_proc_root = TimedFungibleFaucet::distribute_digest();

    let auth_component: AccountComponent = match auth_scheme {
        AuthScheme::Falcon512Rpo { pub_key } => AuthFalcon512RpoAcl::new(
            pub_key,
            AuthFalcon512RpoAclConfig::new()
                .with_auth_trigger_procedures(vec![distribute_proc_root])
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into(),
        AuthScheme::EcdsaK256Keccak { pub_key } => AuthEcdsaK256KeccakAcl::new(
            pub_key,
            AuthEcdsaK256KeccakAclConfig::new()
                .with_auth_trigger_procedures(vec![distribute_proc_root])
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into(),
        AuthScheme::NoAuth => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "timed fungible faucets cannot be created with NoAuth authentication scheme".into(),
            ));
        },
        AuthScheme::Falcon512RpoMultisig { threshold: _, pub_keys: _ } => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "timed fungible faucets do not support multisig authentication".into(),
            ));
        },
        AuthScheme::Unknown => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "timed fungible faucets cannot be created with Unknown authentication scheme"
                    .into(),
            ));
        },
        AuthScheme::EcdsaK256KeccakMultisig { threshold: _, pub_keys: _ } => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "timed fungible faucets do not support EcdsaK256KeccakMultisig authentication"
                    .into(),
            ));
        },
    };

    let faucet_component =
        TimedFungibleFaucet::new(symbol, decimals, max_supply, distribution_end, burn_only)?;

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(storage_mode)
        .with_auth_component(auth_component)
        .with_component(faucet_component)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::account::auth::PublicKeyCommitment;
    use miden_protocol::{FieldElement, ONE, Word};

    use super::{
        AccountBuilder,
        AccountStorageMode,
        AccountType,
        AuthScheme,
        Felt,
        FungibleFaucetError,
        TimedFungibleFaucet,
        TokenSymbol,
        create_timed_fungible_faucet,
    };
    use crate::account::auth::AuthFalcon512Rpo;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn timed_faucet_contract_creation() {
        let pub_key_word = Word::new([ONE; 4]);
        let auth_scheme: AuthScheme = AuthScheme::Falcon512Rpo { pub_key: pub_key_word.into() };

        let init_seed: [u8; 32] = [
            90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85,
            183, 204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
        ];

        let max_supply = Felt::new(1_000_000);
        let token_symbol = TokenSymbol::try_from("TMD").unwrap();
        let decimals = 6u8;
        let distribution_end = 10_000u32;
        let burn_only = true;
        let storage_mode = AccountStorageMode::Private;

        let faucet_account = create_timed_fungible_faucet(
            init_seed,
            token_symbol,
            decimals,
            max_supply,
            distribution_end,
            burn_only,
            storage_mode,
            auth_scheme,
        )
        .unwrap();

        assert!(faucet_account.is_faucet());
        assert_eq!(faucet_account.account_type(), AccountType::FungibleFaucet);

        // Check metadata slot
        assert_eq!(
            faucet_account.storage().get_item(TimedFungibleFaucet::metadata_slot()).unwrap(),
            [Felt::ZERO, max_supply, Felt::new(6), token_symbol.into()].into()
        );

        // Check supply config slot
        assert_eq!(
            faucet_account
                .storage()
                .get_item(TimedFungibleFaucet::supply_config_slot())
                .unwrap(),
            [
                Felt::ZERO,
                max_supply,
                Felt::new(distribution_end as u64),
                Felt::new(burn_only as u64)
            ]
            .into()
        );

        // Verify the faucet can be extracted via TryFrom
        let faucet_component = TimedFungibleFaucet::try_from(faucet_account.clone()).unwrap();
        assert_eq!(faucet_component.symbol(), token_symbol);
        assert_eq!(faucet_component.decimals(), decimals);
        assert_eq!(faucet_component.max_supply(), max_supply);
        assert_eq!(faucet_component.token_supply(), Felt::ZERO);
        assert_eq!(faucet_component.distribution_end(), distribution_end);
        assert_eq!(faucet_component.burn_only(), burn_only);
    }

    #[test]
    fn timed_faucet_create_from_account() {
        let mock_word = Word::from([0, 1, 2, 3u32]);
        let mock_public_key = PublicKeyCommitment::from(mock_word);
        let mock_seed = mock_word.as_bytes();

        let token_symbol = TokenSymbol::new("TMD").expect("invalid token symbol");
        let faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_component(
                TimedFungibleFaucet::new(token_symbol, 6, Felt::new(1_000_000), 10_000, true)
                    .expect("failed to create a timed fungible faucet component"),
            )
            .with_auth_component(AuthFalcon512Rpo::new(mock_public_key))
            .build_existing()
            .expect("failed to create faucet account");

        let timed_ff = TimedFungibleFaucet::try_from(faucet_account)
            .expect("timed fungible faucet creation failed");
        assert_eq!(timed_ff.symbol(), token_symbol);
        assert_eq!(timed_ff.decimals(), 6);
        assert_eq!(timed_ff.max_supply(), Felt::new(1_000_000));
        assert_eq!(timed_ff.token_supply(), Felt::ZERO);
        assert_eq!(timed_ff.distribution_end(), 10_000);
        assert!(timed_ff.burn_only());

        // invalid account: timed fungible faucet component is missing
        let invalid_faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(AuthFalcon512Rpo::new(mock_public_key))
            .with_component(BasicWallet)
            .build_existing()
            .expect("failed to create account");

        let err = TimedFungibleFaucet::try_from(invalid_faucet_account)
            .err()
            .expect("timed fungible faucet creation should fail");
        assert_matches!(err, FungibleFaucetError::MissingTimedFungibleFaucetInterface);
    }

    #[test]
    fn get_timed_faucet_procedures() {
        let _distribute_digest = TimedFungibleFaucet::distribute_digest();
        let _burn_digest = TimedFungibleFaucet::burn_digest();
    }
}
