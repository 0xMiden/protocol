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
use miden_protocol::asset::{FungibleAsset, TokenSymbol};
use miden_protocol::{Felt, FieldElement, Word};

use super::FungibleFaucetError;
use crate::account::AuthScheme;
use crate::account::auth::{
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakAclConfig,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoAclConfig,
};
use crate::account::components::basic_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
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
/// - [`Self::metadata_slot`]: `[token_supply, max_supply, decimals, token_symbol]`, where:
///   - `token_supply` is the current supply of the token.
///   - `max_supply` is the maximum supply of the token.
///   - `decimals` are the decimals of the token.
///   - `token_symbol` is the [`TokenSymbol`] encoded to a [`Felt`].
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct BasicFungibleFaucet {
    token_supply: Felt,
    max_supply: Felt,
    decimals: u8,
    symbol: TokenSymbol,
}

impl BasicFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of decimals supported by the component.
    pub const MAX_DECIMALS: u8 = 12;

    const DISTRIBUTE_PROC_NAME: &str = "basic_fungible_faucet::distribute";
    const BURN_PROC_NAME: &str = "basic_fungible_faucet::burn";

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`BasicFungibleFaucet`] component from the given pieces of metadata and with
    /// an initial token supply of zero.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply parameter exceeds maximum possible amount for a fungible asset
    ///   ([`FungibleAsset::MAX_AMOUNT`])
    pub fn new(
        symbol: TokenSymbol,
        decimals: u8,
        max_supply: Felt,
    ) -> Result<Self, FungibleFaucetError> {
        // First check that the metadata is valid.
        if decimals > Self::MAX_DECIMALS {
            return Err(FungibleFaucetError::TooManyDecimals {
                actual: decimals as u64,
                max: Self::MAX_DECIMALS,
            });
        } else if max_supply.as_int() > FungibleAsset::MAX_AMOUNT {
            return Err(FungibleFaucetError::MaxSupplyTooLarge {
                actual: max_supply.as_int(),
                max: FungibleAsset::MAX_AMOUNT,
            });
        }

        Ok(Self {
            token_supply: Felt::ZERO,
            max_supply,
            decimals,
            symbol,
        })
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
    ///   [`FungibleAsset::MAX_AMOUNT`].
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

        Self::try_from_storage(storage)
    }

    /// Attempts to create a new [`BasicFungibleFaucet`] from the provided account storage.
    ///
    /// # Warning
    ///
    /// This does not check for the presence of the faucet's procedures.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the decimals parameter exceeds maximum value of [`Self::MAX_DECIMALS`].
    /// - the max supply value exceeds maximum possible amount for a fungible asset of
    ///   [`FungibleAsset::MAX_AMOUNT`].
    /// - the token supply exceeds the max supply.
    /// - the token symbol encoded value exceeds the maximum value of
    ///   [`TokenSymbol::MAX_ENCODED_VALUE`].
    pub(super) fn try_from_storage(storage: &AccountStorage) -> Result<Self, FungibleFaucetError> {
        let faucet_metadata =
            storage.get_item(BasicFungibleFaucet::metadata_slot()).map_err(|err| {
                FungibleFaucetError::StorageLookupFailed {
                    slot_name: BasicFungibleFaucet::metadata_slot().clone(),
                    source: err,
                }
            })?;
        let [token_supply, max_supply, decimals, token_symbol] = *faucet_metadata;

        // Convert token symbol and decimals to expected types.
        let token_symbol =
            TokenSymbol::try_from(token_symbol).map_err(FungibleFaucetError::InvalidTokenSymbol)?;
        let decimals =
            decimals.as_int().try_into().map_err(|_| FungibleFaucetError::TooManyDecimals {
                actual: decimals.as_int(),
                max: Self::MAX_DECIMALS,
            })?;

        BasicFungibleFaucet::new(token_symbol, decimals, max_supply)
            .and_then(|fungible_faucet| fungible_faucet.with_token_supply(token_supply))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] where the [`BasicFungibleFaucet`]'s metadata is stored.
    pub fn metadata_slot() -> &'static StorageSlotName {
        &super::METADATA_SLOT_NAME
    }

    /// Returns the symbol of the faucet.
    pub fn symbol(&self) -> TokenSymbol {
        self.symbol
    }

    /// Returns the decimals of the faucet.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns the max supply (in base units) of the faucet.
    ///
    /// This is the highest amount of tokens that can be minted from this faucet.
    pub fn max_supply(&self) -> Felt {
        self.max_supply
    }

    /// Returns the token supply (in base units) of the faucet.
    ///
    /// This is the amount of tokens that were minted from the faucet so far. Its value can never
    /// exceed [`Self::max_supply`].
    pub fn token_supply(&self) -> Felt {
        self.token_supply
    }

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_BURN
    }

    /// Returns the metadata slot [`Word`] of this faucet.
    pub(super) fn to_metadata_word(&self) -> Word {
        Word::new([
            self.token_supply,
            self.max_supply,
            Felt::from(self.decimals),
            Felt::from(self.symbol),
        ])
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
        if token_supply.as_int() > self.max_supply.as_int() {
            return Err(FungibleFaucetError::TokenSupplyExceedsMaxSupply {
                token_supply: token_supply.as_int(),
                max_supply: self.max_supply.as_int(),
            });
        }

        self.token_supply = token_supply;

        Ok(self)
    }
}

impl From<BasicFungibleFaucet> for AccountComponent {
    fn from(faucet: BasicFungibleFaucet) -> Self {
        let metadata_word = faucet.to_metadata_word();
        let storage_slot =
            StorageSlot::with_value(BasicFungibleFaucet::metadata_slot().clone(), metadata_word);

        AccountComponent::new(basic_fungible_faucet_library(), vec![storage_slot])
            .expect("basic fungible faucet component should satisfy the requirements of a valid account component")
            .with_supported_type(AccountType::FungibleFaucet)
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
/// decimals, max supply).
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
/// - [`AuthEcdsaK256KeccakAcl`] or [`AuthFalcon512RpoAcl`]
pub fn create_basic_fungible_faucet(
    init_seed: [u8; 32],
    symbol: TokenSymbol,
    decimals: u8,
    max_supply: Felt,
    account_storage_mode: AccountStorageMode,
    auth_scheme: AuthScheme,
) -> Result<Account, FungibleFaucetError> {
    let distribute_proc_root = BasicFungibleFaucet::distribute_digest();

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
                "basic fungible faucets cannot be created with NoAuth authentication scheme".into(),
            ));
        },
        AuthScheme::Falcon512RpoMultisig { threshold: _, pub_keys: _ } => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "basic fungible faucets do not support multisig authentication".into(),
            ));
        },
        AuthScheme::Unknown => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "basic fungible faucets cannot be created with Unknown authentication scheme"
                    .into(),
            ));
        },
        AuthScheme::EcdsaK256KeccakMultisig { threshold: _, pub_keys: _ } => {
            return Err(FungibleFaucetError::UnsupportedAuthScheme(
                "basic fungible faucets do not support EcdsaK256KeccakMultisig authentication"
                    .into(),
            ));
        },
    };

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(account_storage_mode)
        .with_auth_component(auth_component)
        .with_component(BasicFungibleFaucet::new(symbol, decimals, max_supply)?)
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
        BasicFungibleFaucet,
        Felt,
        FungibleFaucetError,
        TokenSymbol,
        create_basic_fungible_faucet,
    };
    use crate::account::auth::{AuthFalcon512Rpo, AuthFalcon512RpoAcl};
    use crate::account::wallets::BasicWallet;

    #[test]
    fn faucet_contract_creation() {
        let pub_key_word = Word::new([ONE; 4]);
        let auth_scheme: AuthScheme = AuthScheme::Falcon512Rpo { pub_key: pub_key_word.into() };

        // we need to use an initial seed to create the wallet account
        let init_seed: [u8; 32] = [
            90, 110, 209, 94, 84, 105, 250, 242, 223, 203, 216, 124, 22, 159, 14, 132, 215, 85,
            183, 204, 149, 90, 166, 68, 100, 73, 106, 168, 125, 237, 138, 16,
        ];

        let max_supply = Felt::new(123);
        let token_symbol_string = "POL";
        let token_symbol = TokenSymbol::try_from(token_symbol_string).unwrap();
        let decimals = 2u8;
        let storage_mode = AccountStorageMode::Private;

        let faucet_account = create_basic_fungible_faucet(
            init_seed,
            token_symbol,
            decimals,
            max_supply,
            storage_mode,
            auth_scheme,
        )
        .unwrap();

        // The falcon auth component's public key should be present.
        assert_eq!(
            faucet_account
                .storage()
                .get_item(AuthFalcon512RpoAcl::public_key_slot())
                .unwrap(),
            pub_key_word
        );

        // The config slot of the auth component stores:
        // [num_trigger_procs, allow_unauthorized_output_notes, allow_unauthorized_input_notes, 0].
        //
        // With 1 trigger procedure (distribute), allow_unauthorized_output_notes=false, and
        // allow_unauthorized_input_notes=true, this should be [1, 0, 1, 0].
        assert_eq!(
            faucet_account.storage().get_item(AuthFalcon512RpoAcl::config_slot()).unwrap(),
            [Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ZERO].into()
        );

        // The procedure root map should contain the distribute procedure root.
        let distribute_root = BasicFungibleFaucet::distribute_digest();
        assert_eq!(
            faucet_account
                .storage()
                .get_map_item(
                    AuthFalcon512RpoAcl::trigger_procedure_roots_slot(),
                    [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
                )
                .unwrap(),
            distribute_root
        );

        // Check that faucet metadata was initialized to the given values.
        assert_eq!(
            faucet_account.storage().get_item(BasicFungibleFaucet::metadata_slot()).unwrap(),
            [Felt::ZERO, Felt::new(123), Felt::new(2), token_symbol.into()].into()
        );

        assert!(faucet_account.is_faucet());

        assert_eq!(faucet_account.account_type(), AccountType::FungibleFaucet);

        // Verify the faucet can be extracted and has correct metadata
        let faucet_component = BasicFungibleFaucet::try_from(faucet_account.clone()).unwrap();
        assert_eq!(faucet_component.symbol(), token_symbol);
        assert_eq!(faucet_component.decimals(), decimals);
        assert_eq!(faucet_component.max_supply(), max_supply);
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
                BasicFungibleFaucet::new(token_symbol, 10, Felt::new(100))
                    .expect("failed to create a fungible faucet component"),
            )
            .with_auth_component(AuthFalcon512Rpo::new(mock_public_key))
            .build_existing()
            .expect("failed to create wallet account");

        let basic_ff = BasicFungibleFaucet::try_from(faucet_account)
            .expect("basic fungible faucet creation failed");
        assert_eq!(basic_ff.symbol, token_symbol);
        assert_eq!(basic_ff.decimals, 10);
        assert_eq!(basic_ff.max_supply, Felt::new(100));

        // invalid account: basic fungible faucet component is missing
        let invalid_faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_auth_component(AuthFalcon512Rpo::new(mock_public_key))
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
