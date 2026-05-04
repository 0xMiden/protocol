use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorage,
    AccountStorageMode,
    AccountType,
};

use super::FungibleFaucetError;
use crate::account::AuthMethod;
use crate::account::auth::{AuthSingleSigAcl, AuthSingleSigAclConfig};
use crate::account::components::basic_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::metadata::FungibleTokenMetadata;
use crate::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyAuthority,
    TokenPolicyManager,
};
use crate::procedure_digest;

// BASIC FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `mint_and_send` procedure of the Basic Fungible Faucet only once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_MINT_AND_SEND,
    BasicFungibleFaucet::NAME,
    BasicFungibleFaucet::MINT_PROC_NAME,
    basic_fungible_faucet_library
);

// Initialize the digest of the `burn` procedure of the Basic Fungible Faucet only once.
procedure_digest!(
    BASIC_FUNGIBLE_FAUCET_BURN,
    BasicFungibleFaucet::NAME,
    BasicFungibleFaucet::BURN_PROC_NAME,
    basic_fungible_faucet_library
);

/// An [`AccountComponent`] implementing a basic fungible faucet.
///
/// It reexports the procedures from `miden::standards::faucets::basic_fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `mint_and_send`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// The `mint_and_send` procedure can be called from a transaction script and requires
/// authentication via the authentication component. The `burn` procedure can only be called from a
/// note script and requires the calling note to contain the asset to be burned.
/// This component must be combined with an authentication component.
///
/// This component supports accounts of type [`AccountType::FungibleFaucet`].
///
/// This component depends on [`FungibleTokenMetadata`] being present in the account for storage
/// of token metadata. It has no storage slots of its own.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct BasicFungibleFaucet;

impl BasicFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::basic_fungible_faucet";

    const MINT_PROC_NAME: &str = "mint_and_send";
    const BURN_PROC_NAME: &str = "burn";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the digest of the `mint_and_send` account procedure.
    pub fn mint_and_send_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_MINT_AND_SEND
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *BASIC_FUNGIBLE_FAUCET_BURN
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description("Basic fungible faucet component for minting and burning tokens")
    }

    /// Checks that the account contains the basic fungible faucet interface.
    fn try_from_interface(
        interface: AccountInterface,
        _storage: &AccountStorage,
    ) -> Result<Self, FungibleFaucetError> {
        if !interface.components().contains(&AccountComponentInterface::BasicFungibleFaucet) {
            return Err(FungibleFaucetError::MissingBasicFungibleFaucetInterface);
        }

        Ok(BasicFungibleFaucet)
    }
}

impl From<BasicFungibleFaucet> for AccountComponent {
    fn from(_faucet: BasicFungibleFaucet) -> Self {
        let metadata = BasicFungibleFaucet::component_metadata();

        AccountComponent::new(basic_fungible_faucet_library(), vec![], metadata)
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
/// account storage type, specified authentication scheme, and provided metadata.
///
/// The basic faucet interface exposes two procedures:
/// - `mint_and_send`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// The `mint_and_send` procedure can be called from a transaction script and requires
/// authentication via the specified authentication scheme. The `burn` procedure can only be called
/// from a note script and requires the calling note to contain the asset to be burned.
///
/// The storage layout of the faucet account is defined by the combination of the following
/// components (see their docs for details):
/// - [`FungibleTokenMetadata`] (token metadata, name, description, etc.)
/// - [`BasicFungibleFaucet`] (mint_and_send and burn procedures)
/// - [`AuthSingleSigAcl`]
/// - [`TokenPolicyManager`] + the active mint and burn policy components produced by the
///   [`MintPolicyConfig`] and [`BurnPolicyConfig`] passed to it (here: `MintAllowAll` and
///   `BurnAllowAll`).
///
/// Component dependency graph:
/// ```text
/// BasicFungibleFaucet
/// └── TokenPolicyManager (auth-controlled)
///     ├── MintAllowAll  (active mint policy)
///     └── BurnAllowAll  (active burn policy)
/// ```
pub fn create_basic_fungible_faucet(
    init_seed: [u8; 32],
    metadata: FungibleTokenMetadata,
    account_storage_mode: AccountStorageMode,
    auth_method: AuthMethod,
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

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(account_storage_mode)
        .with_auth_component(auth_component)
        .with_component(metadata)
        .with_component(BasicFungibleFaucet)
        .with_components(TokenPolicyManager::new(
            PolicyAuthority::AuthControlled,
            MintPolicyConfig::AllowAll,
            BurnPolicyConfig::AllowAll,
        ))
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

    use super::{
        AccountBuilder,
        AccountStorageMode,
        AccountType,
        AuthMethod,
        BasicFungibleFaucet,
        FungibleFaucetError,
        FungibleTokenMetadata,
        create_basic_fungible_faucet,
    };
    use crate::account::auth::{AuthSingleSig, AuthSingleSigAcl};
    use crate::account::metadata::{
        Description,
        FungibleTokenMetadataBuilder,
        TokenMetadata,
        TokenName,
    };
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
        let metadata = FungibleTokenMetadataBuilder::new(
            token_name,
            token_symbol.clone(),
            decimals,
            max_supply,
        )
        .description(description)
        .build()
        .unwrap();
        let faucet_account =
            create_basic_fungible_faucet(init_seed, metadata, storage_mode, auth_method).unwrap();

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
                .get_item(FungibleTokenMetadata::metadata_slot())
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
        let metadata = FungibleTokenMetadataBuilder::new(
            TokenName::new("POL").unwrap(),
            token_symbol,
            10,
            100u64,
        )
        .build()
        .expect("failed to create token metadata");

        let faucet_account = AccountBuilder::new(mock_seed)
            .account_type(AccountType::FungibleFaucet)
            .with_component(metadata)
            .with_component(BasicFungibleFaucet)
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
        let _burn_digest = BasicFungibleFaucet::burn_digest();
    }
}
