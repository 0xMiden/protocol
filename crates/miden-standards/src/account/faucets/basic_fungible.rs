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

use super::{Description, ExternalLink, FungibleFaucetError, LogoURI, TokenMetadata, TokenName};
use crate::account::AuthMethod;
use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig};
use crate::account::components::basic_fungible_faucet_library;

/// The schema type for token symbols.
const TOKEN_SYMBOL_TYPE: &str = "miden::standards::fungible_faucets::metadata::token_symbol";
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::metadata::Info;
use crate::procedure_digest;

// BASIC FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `distribute` procedure of the Basic Fungible Faucet only once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_DISTRIBUTE,
    BasicFungibleFaucet::DISTRIBUTE_PROC_NAME,
    basic_fungible_faucet_library
);

// Initialize the digest of the `burn` procedure of the Basic Fungible Faucet only once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_BURN,
    BasicFungibleFaucet::BURN_PROC_NAME,
    basic_fungible_faucet_library
);

/// An [`AccountComponent`] implementing a basic fungible faucet.
///
/// It reexports the procedures from `miden::standards::faucets::basic_fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// The `distribute` procedure can be called from a transaction script and requires authentication
/// via the authentication component. The `burn` procedure can only be called from a note script
/// and requires the calling note to contain the asset to be burned.
/// This component must be combined with an authentication component.
///
/// This component supports accounts of type [`AccountType::FungibleFaucet`].
///
/// ## Storage Layout
///
/// - [`Self::metadata_slot`]: Stores [`TokenMetadata`].
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct BasicFungibleFaucet {
    metadata: TokenMetadata,
}

impl BasicFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::basic_fungible_faucet";

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = TokenMetadata::MAX_DECIMALS;

    const DISTRIBUTE_PROC_NAME: &str = "basic_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "basic_fungible_faucet::burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BasicFungibleFaucet`] component from the given pieces of metadata and with
    /// an initial token supply of zero.
    ///
    /// Optional `description`, `logo_uri`, and `external_link` are stored in the metadata
    /// [`Info`][Info] component when building an account (e.g. via
    /// [`create_basic_fungible_faucet`]).
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
        name: TokenName,
        description: Option<Description>,
        logo_uri: Option<LogoURI>,
        external_link: Option<ExternalLink>,
    ) -> Result<Self, FungibleFaucetError> {
        let metadata = TokenMetadata::new(
            symbol,
            decimals,
            max_supply,
            name,
            description,
            logo_uri,
            external_link,
        )?;
        Ok(Self { metadata })
    }

    /// Creates a new [`BasicFungibleFaucet`] component from the given [`TokenMetadata`].
    ///
    /// This is a convenience constructor that allows creating a faucet from pre-validated
    /// metadata.
    pub fn from_metadata(metadata: TokenMetadata) -> Self {
        Self { metadata }
    }

    /// Attempts to create a new [`BasicFungibleFaucet`] component from the associated account
    /// interface and storage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided [`AccountInterface`] does not contain a
    ///   [`AccountComponentInterface::BasicFungibleFaucet`] component.
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
        // Check that the procedures of the basic fungible faucet exist in the account.
        if !interface.components().contains(&AccountComponentInterface::BasicFungibleFaucet) {
            return Err(FungibleFaucetError::MissingBasicFungibleFaucetInterface);
        }

        let metadata = TokenMetadata::try_from(storage)?;
        Ok(Self { metadata })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`BasicFungibleFaucet`]'s metadata is stored (slot
    /// 0).
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

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_BURN
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the token_supply (in base units) of the basic fungible faucet.
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

impl From<BasicFungibleFaucet> for AccountComponent {
    fn from(faucet: BasicFungibleFaucet) -> Self {
        let storage_slot = faucet.metadata.into();

        let storage_schema = StorageSchema::new([BasicFungibleFaucet::metadata_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(BasicFungibleFaucet::NAME)
            .with_description("Basic fungible faucet component for minting and burning tokens")
            .with_supported_type(AccountType::FungibleFaucet)
            .with_storage_schema(storage_schema);

        AccountComponent::new(basic_fungible_faucet_library(), vec![storage_slot], metadata)
            .expect("basic fungible faucet component should satisfy the requirements of a valid account component")
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

/// Creates a new faucet account with basic fungible faucet interface,
/// account storage type, specified authentication scheme, and provided meta data (token symbol,
/// decimals, max supply). Optional `name`, `description`, `logo_uri`, and `external_link` are
/// stored in the metadata [`Info`][Info] component when provided.
///
/// The basic faucet interface exposes two procedures:
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// The `distribute` procedure can be called from a transaction script and requires authentication
/// via the specified authentication scheme. The `burn` procedure can only be called from a note
/// script and requires the calling note to contain the asset to be burned.
///
/// The storage layout of the faucet account is defined by the combination of the following
/// components (see their docs for details):
/// - [`BasicFungibleFaucet`]
/// - [`AuthSingleSigAcl`]
/// - [`Info`][Info] (when `name` or optional fields are provided)
#[allow(clippy::too_many_arguments)]
pub fn create_basic_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    account_storage_mode: AccountStorageMode,
    auth_method: AuthMethod,
    name: TokenName,
    description: Option<Description>,
    logo_uri: Option<LogoURI>,
    external_link: Option<ExternalLink>,
) -> Result<Account, FungibleFaucetError> {
    let distribute_proc_root = BasicFungibleFaucet::distribute_digest();

    let auth_component: AccountComponent = match auth_method {
        AuthMethod::SingleSig { approver: (pub_key, auth_scheme) } => AuthSingleSigAcl::new(
            pub_key,
            auth_scheme,
            AuthSingleSigAclConfig::new()
                .with_auth_trigger_procedures(vec![distribute_proc_root])
                .with_allow_unauthorized_input_notes(true),
        )
        .map_err(FungibleFaucetError::AccountError)?
        .into(),
        AuthMethod::NoAuth => {
            return Err(FungibleFaucetError::UnsupportedAuthMethod(
                "basic fungible faucets cannot be created with NoAuth authentication method".into(),
            ));
        },
        AuthMethod::Unknown => {
            return Err(FungibleFaucetError::UnsupportedAuthMethod(
                "basic fungible faucets cannot be created with Unknown authentication method"
                    .into(),
            ));
        },
        AuthMethod::Multisig { .. } => {
            return Err(FungibleFaucetError::UnsupportedAuthMethod(
                "basic fungible faucets do not support Multisig authentication".into(),
            ));
        },
    };

    let faucet = BasicFungibleFaucet::new(
        symbol,
        decimals,
        max_supply,
        name,
        description,
        logo_uri,
        external_link,
    )?;

    let mut info = Info::new().with_name(name.as_words());
    if let Some(d) = &description {
        info = info.with_description(d.as_words(), false);
    }
    if let Some(l) = &logo_uri {
        info = info.with_logo_uri(l.as_words(), false);
    }
    if let Some(e) = &external_link {
        info = info.with_external_link(e.as_words(), false);
    }

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(account_storage_mode)
        .with_auth_component(auth_component)
        .with_component(faucet)
        .with_component(info)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use miden_protocol::Word;
    use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};

    use super::{
        AccountBuilder,
        AccountStorageMode,
        AccountType,
        AuthMethod,
        BasicFungibleFaucet,
        Description,
        Felt,
        FungibleFaucetError,
        TokenName,
        TokenSymbol,
        create_basic_fungible_faucet,
    };
    use crate::account::auth::{AuthSingleSig, AuthSingleSigAcl};
    use crate::account::metadata::{self as account_metadata, Info};
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

        let max_supply = Felt::new(123);
        let token_symbol_string = "POL";
        let token_symbol = TokenSymbol::try_from(token_symbol_string).unwrap();
        let token_name_string = "polygon";
        let description_string = "A polygon token";
        let decimals = 2u8;
        let storage_mode = AccountStorageMode::Private;

        let token_name = TokenName::try_from(token_name_string).unwrap();
        let description = Description::try_from(description_string).unwrap();
        let faucet_account = create_basic_fungible_faucet(
            init_seed,
            token_symbol,
            decimals,
            max_supply,
            storage_mode,
            auth_method,
            token_name,
            Some(description),
            None,
            None,
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
        // With 1 trigger procedure (distribute), allow_unauthorized_output_notes=false, and
        // allow_unauthorized_input_notes=true, this should be [1, 0, 1, 0].
        assert_eq!(
            faucet_account.storage().get_item(AuthSingleSigAcl::config_slot()).unwrap(),
            [Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ZERO].into()
        );

        // The procedure root map should contain the distribute procedure root.
        let distribute_root = BasicFungibleFaucet::distribute_digest();
        assert_eq!(
            faucet_account
                .storage()
                .get_map_item(
                    AuthSingleSigAcl::trigger_procedure_roots_slot(),
                    [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
                )
                .unwrap(),
            distribute_root
        );

        // Check that faucet metadata was initialized to the given values.
        // Storage layout: [token_supply, max_supply, decimals, symbol]
        assert_eq!(
            faucet_account.storage().get_item(BasicFungibleFaucet::metadata_slot()).unwrap(),
            [Felt::ZERO, Felt::new(123), Felt::new(2), token_symbol.into()].into()
        );

        // Check that Info component has name and description
        let name_0 = faucet_account.storage().get_item(Info::name_chunk_0_slot()).unwrap();
        let name_1 = faucet_account.storage().get_item(Info::name_chunk_1_slot()).unwrap();
        let decoded_name = account_metadata::name_to_utf8(&[name_0, name_1]).unwrap();
        assert_eq!(decoded_name, token_name_string);
        let expected_desc_words =
            account_metadata::field_from_bytes(description_string.as_bytes()).unwrap();
        for (i, expected) in expected_desc_words.iter().enumerate() {
            let chunk = faucet_account.storage().get_item(Info::description_slot(i)).unwrap();
            assert_eq!(chunk, *expected);
        }

        assert!(faucet_account.is_faucet());

        assert_eq!(faucet_account.account_type(), AccountType::FungibleFaucet);

        // Verify the faucet can be extracted and has correct metadata
        let faucet_component = BasicFungibleFaucet::try_from(faucet_account.clone()).unwrap();
        assert_eq!(faucet_component.symbol(), token_symbol);
        assert_eq!(faucet_component.decimals(), decimals);
        assert_eq!(faucet_component.max_supply(), max_supply);
        assert_eq!(faucet_component.token_supply(), Felt::ZERO);
    }

    #[test]
    fn faucet_create_from_account() {
        // prepare the test data
        let mock_word = Word::from([0, 1, 2, 3u32]);
        let mock_public_key = PublicKeyCommitment::from(mock_word);
        let mock_seed = mock_word.as_bytes();

        // valid account
        let token_symbol = TokenSymbol::new("POL").expect("invalid token symbol");
        let faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_component(
                BasicFungibleFaucet::new(
                    token_symbol,
                    10,
                    Felt::new(100),
                    TokenName::try_from("POL").unwrap(),
                    None,
                    None,
                    None,
                )
                .expect("failed to create a fungible faucet component"),
            )
            .with_auth_component(AuthSingleSig::new(
                mock_public_key,
                AuthScheme::Falcon512Poseidon2,
            ))
            .build_existing()
            .expect("failed to create wallet account");

        let basic_ff = BasicFungibleFaucet::try_from(faucet_account)
            .expect("basic fungible faucet creation failed");
        assert_eq!(basic_ff.symbol(), token_symbol);
        assert_eq!(basic_ff.decimals(), 10);
        assert_eq!(basic_ff.max_supply(), Felt::new(100));
        assert_eq!(basic_ff.token_supply(), Felt::ZERO);

        // invalid account: basic fungible faucet component is missing
        let invalid_faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(AuthSingleSig::new(mock_public_key, AuthScheme::Falcon512Poseidon2))
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
        let _distribute_digest = BasicFungibleFaucet::distribute_digest();
        let _burn_digest = BasicFungibleFaucet::burn_digest();
    }
}
