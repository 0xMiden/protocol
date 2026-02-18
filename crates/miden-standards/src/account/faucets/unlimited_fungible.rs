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
use miden_protocol::{Felt, Word};

use super::{FungibleFaucetError, TokenMetadata};
use crate::account::AuthScheme;
use crate::account::auth::{
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakAclConfig,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoAclConfig,
};
use crate::account::components::unlimited_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::procedure_digest;

/// The schema type ID for token symbols.
const TOKEN_SYMBOL_TYPE_ID: &str = "miden::standards::fungible_faucets::metadata::token_symbol";

// UNLIMITED FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

procedure_digest!(
    UNLIMITED_FUNGIBLE_FAUCET_DISTRIBUTE,
    UnlimitedFungibleFaucet::DISTRIBUTE_PROC_NAME,
    unlimited_fungible_faucet_library
);

procedure_digest!(
    UNLIMITED_FUNGIBLE_FAUCET_BURN,
    UnlimitedFungibleFaucet::BURN_PROC_NAME,
    unlimited_fungible_faucet_library
);

/// An [`AccountComponent`] implementing an unlimited fungible faucet.
///
/// It reexports the procedures from `miden::standards::faucets::unlimited_fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `distribute`, which mints assets and creates a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// No supply checks are enforced — minting is unrestricted up to protocol limits
/// ([`FungibleAsset::MAX_AMOUNT`](miden_protocol::asset::FungibleAsset::MAX_AMOUNT)).
///
/// This component supports accounts of type [`AccountType::FungibleFaucet`].
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Stores [`TokenMetadata`].
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct UnlimitedFungibleFaucet {
    metadata: TokenMetadata,
}

impl UnlimitedFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::unlimited_fungible_faucet";

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = TokenMetadata::MAX_DECIMALS;

    const DISTRIBUTE_PROC_NAME: &str = "unlimited_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "unlimited_fungible_faucet::burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`UnlimitedFungibleFaucet`] component.
    ///
    /// The max supply is set to
    /// [`FungibleAsset::MAX_AMOUNT`](miden_protocol::asset::FungibleAsset::MAX_AMOUNT)
    /// since this faucet does not enforce supply limits at runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    pub fn new(symbol: TokenSymbol, decimals: u8) -> Result<Self, FungibleFaucetError> {
        let max_supply = miden_protocol::asset::FungibleAsset::MAX_AMOUNT;
        let metadata = TokenMetadata::new(symbol, decimals, Felt::new(max_supply))?;
        Ok(Self { metadata })
    }

    /// Creates a new [`UnlimitedFungibleFaucet`] component from the given [`TokenMetadata`].
    pub fn from_metadata(metadata: TokenMetadata) -> Self {
        Self { metadata }
    }

    /// Attempts to create a new [`UnlimitedFungibleFaucet`] component from the associated account
    /// interface and storage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided [`AccountInterface`] does not contain a
    ///   [`AccountComponentInterface::UnlimitedFungibleFaucet`] component.
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
        if !interface
            .components()
            .contains(&AccountComponentInterface::UnlimitedFungibleFaucet)
        {
            return Err(FungibleFaucetError::MissingUnlimitedFungibleFaucetInterface);
        }

        let metadata = TokenMetadata::try_from(storage)?;
        Ok(Self { metadata })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`UnlimitedFungibleFaucet`]'s metadata is stored.
    pub fn metadata_slot() -> &'static StorageSlotName {
        TokenMetadata::metadata_slot()
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

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *UNLIMITED_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *UNLIMITED_FUNGIBLE_FAUCET_BURN
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the token_supply (in base units) of the unlimited fungible faucet.
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

impl From<UnlimitedFungibleFaucet> for AccountComponent {
    fn from(faucet: UnlimitedFungibleFaucet) -> Self {
        let storage_slot: StorageSlot = faucet.metadata.into();

        let storage_schema = StorageSchema::new([UnlimitedFungibleFaucet::metadata_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(UnlimitedFungibleFaucet::NAME)
            .with_description("Unlimited fungible faucet component for minting and burning tokens")
            .with_supported_type(AccountType::FungibleFaucet)
            .with_storage_schema(storage_schema);

        AccountComponent::new(unlimited_fungible_faucet_library(), vec![storage_slot], metadata)
            .expect("unlimited fungible faucet component should satisfy the requirements of a valid account component")
    }
}

impl TryFrom<Account> for UnlimitedFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(&account);

        UnlimitedFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for UnlimitedFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(account);

        UnlimitedFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

/// Creates a new faucet account with unlimited fungible faucet interface,
/// account storage type, specified authentication scheme, and provided metadata (token symbol,
/// decimals).
///
/// The unlimited faucet interface exposes two procedures:
/// - `distribute`, which mints assets and creates a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// No supply checks are enforced at runtime.
pub fn create_unlimited_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    storage_mode: AccountStorageMode,
    auth_scheme: AuthScheme,
) -> Result<Account, FungibleFaucetError> {
    let distribute_proc_root = UnlimitedFungibleFaucet::distribute_digest();

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
                "unlimited fungible faucets cannot be created with NoAuth authentication scheme"
                    .into(),
            ));
        },
        AuthScheme::Falcon512RpoMultisig { threshold: _, pub_keys: _ } => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "unlimited fungible faucets do not support multisig authentication".into(),
            ));
        },
        AuthScheme::Unknown => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "unlimited fungible faucets cannot be created with Unknown authentication scheme"
                    .into(),
            ));
        },
        AuthScheme::EcdsaK256KeccakMultisig { threshold: _, pub_keys: _ } => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "unlimited fungible faucets do not support EcdsaK256KeccakMultisig authentication"
                    .into(),
            ));
        },
    };

    let faucet_component = UnlimitedFungibleFaucet::new(symbol, decimals)?;

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
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::{FieldElement, ONE, Word};

    use super::{
        AccountBuilder,
        AccountStorageMode,
        AccountType,
        AuthScheme,
        Felt,
        FungibleFaucetError,
        TokenSymbol,
        UnlimitedFungibleFaucet,
        create_unlimited_fungible_faucet,
    };
    use crate::account::auth::AuthFalcon512Rpo;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn unlimited_faucet_contract_creation() {
        let pub_key_word = Word::new([ONE; 4]);
        let auth_scheme: AuthScheme = AuthScheme::Falcon512Rpo { pub_key: pub_key_word.into() };

        let init_seed: [u8; 32] = [
            90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85,
            183, 204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
        ];

        let token_symbol = TokenSymbol::try_from("UNL").unwrap();
        let decimals = 8u8;
        let storage_mode = AccountStorageMode::Private;

        let faucet_account = create_unlimited_fungible_faucet(
            init_seed,
            token_symbol,
            decimals,
            storage_mode,
            auth_scheme,
        )
        .unwrap();

        assert!(faucet_account.is_faucet());
        assert_eq!(faucet_account.account_type(), AccountType::FungibleFaucet);

        // Check metadata slot: max_supply should be FungibleAsset::MAX_AMOUNT
        assert_eq!(
            faucet_account
                .storage()
                .get_item(UnlimitedFungibleFaucet::metadata_slot())
                .unwrap(),
            [
                Felt::ZERO,
                Felt::new(FungibleAsset::MAX_AMOUNT),
                Felt::new(8),
                token_symbol.into()
            ]
            .into()
        );

        // Verify the faucet can be extracted via TryFrom
        let faucet_component = UnlimitedFungibleFaucet::try_from(faucet_account.clone()).unwrap();
        assert_eq!(faucet_component.symbol(), token_symbol);
        assert_eq!(faucet_component.decimals(), decimals);
        assert_eq!(faucet_component.max_supply(), Felt::new(FungibleAsset::MAX_AMOUNT));
        assert_eq!(faucet_component.token_supply(), Felt::ZERO);
    }

    #[test]
    fn unlimited_faucet_create_from_account() {
        let mock_word = Word::from([0, 1, 2, 3u32]);
        let mock_public_key = PublicKeyCommitment::from(mock_word);
        let mock_seed = mock_word.as_bytes();

        let token_symbol = TokenSymbol::new("UNL").expect("invalid token symbol");
        let faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_component(
                UnlimitedFungibleFaucet::new(token_symbol, 8)
                    .expect("failed to create an unlimited fungible faucet component"),
            )
            .with_auth_component(AuthFalcon512Rpo::new(mock_public_key))
            .build_existing()
            .expect("failed to create faucet account");

        let unlimited_ff = UnlimitedFungibleFaucet::try_from(faucet_account)
            .expect("unlimited fungible faucet creation failed");
        assert_eq!(unlimited_ff.symbol(), token_symbol);
        assert_eq!(unlimited_ff.decimals(), 8);
        assert_eq!(unlimited_ff.token_supply(), Felt::ZERO);

        // invalid account: unlimited fungible faucet component is missing
        let invalid_faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(AuthFalcon512Rpo::new(mock_public_key))
            .with_component(BasicWallet)
            .build_existing()
            .expect("failed to create account");

        let err = UnlimitedFungibleFaucet::try_from(invalid_faucet_account)
            .err()
            .expect("unlimited fungible faucet creation should fail");
        assert_matches!(err, FungibleFaucetError::MissingUnlimitedFungibleFaucetInterface);
    }

    #[test]
    fn get_unlimited_faucet_procedures() {
        let _distribute_digest = UnlimitedFungibleFaucet::distribute_digest();
        let _burn_digest = UnlimitedFungibleFaucet::burn_digest();
    }
}
